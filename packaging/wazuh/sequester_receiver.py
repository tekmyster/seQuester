#!/usr/bin/env python3
"""Bounded TLS syslog receiver with durable receipts and a Wazuh/Filebeat journal.

The SQLite journal is authoritative. JSONL export is at least once; document_id
deduplicates indexing across a crash between append/fsync and export commit.
"""
import argparse,datetime,hashlib,ipaddress,json,os,pathlib,re,signal,socket,sqlite3,ssl,threading,time

MAX_FRAME=60000
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def wazuh_ready(journal_directory,wazuh_directory='/var/ossec',proc_directory='/proc',now=None):
    """Require a fresh collector state from the current collector instance.
    Wazuh begins a new file source at EOF, so defer projection appends until
    its source is open. Stale state from before restart cannot authorize export.
    """
    try:
        now=time.time() if now is None else now;proc=pathlib.Path(proc_directory);path=pathlib.Path(wazuh_directory)/'var/run/wazuh-logcollector.state';stat=path.stat()
        if not -30<=now-stat.st_mtime<=90:return False
        state=json.loads(path.read_text());source=str(pathlib.Path(journal_directory)/'rules.jsonl')
        if not any(row.get('location')==source for row in state.get('global',{}).get('files',[])):return False
        uptime=float((proc/'uptime').read_text().split()[0]);frequency=os.sysconf('SC_CLK_TCK')
        for directory in proc.iterdir():
            if not directory.name.isdigit():continue
            try:
                if (directory/'comm').read_text().strip()!='wazuh-logcollec':continue
                fields=(directory/'stat').read_text().rsplit(') ',1)[1].split();started=now-uptime+int(fields[19])/frequency
                if stat.st_mtime>=started:return True
            except (OSError,ValueError,IndexError):continue
        return False
    except (OSError,ValueError,TypeError,KeyError,IndexError):return False
class Journal:
    def __init__(self,root,maximum_bytes=1024*1024*1024,rotation_bytes=128*1024*1024,ready=None):
        if not isinstance(maximum_bytes,int) or maximum_bytes<MAX_FRAME*4 or not isinstance(rotation_bytes,int) or not MAX_FRAME<=rotation_bytes<=maximum_bytes:raise ValueError('Invalid journal capacity')
        self.maximum_bytes=maximum_bytes;self.rotation_bytes=rotation_bytes;self.ready=ready
        self.root=pathlib.Path(root);self.root.mkdir(parents=True,exist_ok=True);self.lock=threading.RLock()
        self.db=sqlite3.connect(self.root/'events.db',timeout=10,check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,sensor TEXT NOT NULL,event_id TEXT NOT NULL,sha256 TEXT NOT NULL,record TEXT NOT NULL,exported INTEGER NOT NULL DEFAULT 0,UNIQUE(sensor,event_id))');self.db.commit()
        # Empty sources must exist before the collector can register them.
        for name in ['events.jsonl','rules.jsonl']:
            try:
                with (self.root/name).open('xb'):pass
            except FileExistsError:pass
    def accept(self,frame,peer):
        if not 1<=len(frame)<=MAX_FRAME:raise ValueError('Invalid frame length')
        start=frame.find(b'{')
        if start<0 or not re.fullmatch(rb'<[0-9]{1,3}>1 [^ ]+ [^ ]+ RansomFree [^ ]+ [^ ]+ - ',frame[:start]):raise ValueError('Unsupported producer')
        payload=frame[start:];event=json.loads(payload.decode('utf-8','strict'))
        if not isinstance(event,dict):raise ValueError('Object required')
        event_id=event.get('EventId');sensor=event.get('EndpointId') or 'server'
        if not isinstance(event_id,str) or not re.fullmatch('[a-fA-F0-9]{32}',event_id) or not isinstance(sensor,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',sensor):raise ValueError('Stable event identity required')
        digest=hashlib.sha256(payload).hexdigest().upper();document=hashlib.sha256((sensor+'|'+event_id).encode()).hexdigest()
        def object_field(value,key):
            child=value.get(key)
            if child is None:return {}
            if not isinstance(child,dict):raise ValueError('Invalid evidence object')
            return child
        forensic=object_field(event,'Forensics');executable=object_field(forensic,'ActorExecutable');trust=object_field(event,'Trust');actor=object_field(trust,'Actor')
        process=object_field(forensic,'Process');owner=object_field(process,'Owner');effective=object_field(process,'EffectiveThreadContext');detection=object_field(forensic,'Detection')
        suppressed=event.get('NotificationSuppressed') is True;provider=event.get('Source')
        kind='evidence' if provider in ['Forensic enrichment','Evidence transfer'] else 'health' if isinstance(provider,str) and ('health' in provider.lower() or 'integrity' in provider.lower() or 'response' in provider.lower()) else 'detection'
        record={'sequester_schema_version':1,'document_id':document,'event_id':event_id,'sensor_id':sensor,'host':event.get('Machine'),'forwarded_by':event.get('ForwardedBy'),'notification_suppressed':suppressed,
                'record_kind':kind,'process_pid':event.get('ProcessId'),'actor_sha256':executable.get('Sha256') or actor.get('Sha256'),'received_utc':utc(),'transport_peer':peer,
                'payload_sha256':digest,'syslog_frame_sha256':hashlib.sha256(frame).hexdigest().upper(),'syslog_header':frame[:start].decode('utf-8','strict'),'evidence':event}
        # Keep the original host independent of Filebeat's collector host
        # metadata, which can populate or replace the ECS `host` field.
        record['sensor_host']=event.get('Machine')
        # Wazuh's rule engine gets a bounded projection. Filebeat indexes the
        # complete evidence journal separately, avoiding decoder field limits.
        record['rule_projection']={'sequester_schema_version':1,'document_id':document,'event_id':event_id,'sensor_id':sensor,'host':event.get('Machine'),
            'forwarded_by':event.get('ForwardedBy'),'notification_suppressed':suppressed,'record_kind':kind,'process_pid':event.get('ProcessId'),
            'process_instance_id':process.get('InstanceId'),'process_start_key':process.get('StartKey'),'process_owner_sid':owner.get('Sid'),
            'process_owner_uid':owner.get('Uid'),'effective_sid':effective.get('Sid'),'effective_uid':process.get('EventSubject',{}).get('FileSystemUid') if isinstance(process.get('EventSubject'),dict) else None,
            'process_owner_context_reason':owner.get('Status',{}).get('Reason') if isinstance(owner.get('Status'),dict) else None,
            'effective_context_reason':effective.get('Status',{}).get('Reason') if isinstance(effective.get('Status'),dict) else None,
            'user':event.get('User'),'process_path':event.get('Process'),'source_ip':event.get('SourceAddress'),
            'impersonating':process.get('Impersonating'),'actor_sha256':record['actor_sha256'],'operation':event.get('Operation'),'target_path':event.get('Path'),
            'source':provider,'observed_utc':event.get('Time'),'received_utc':record['received_utc'],'payload_sha256':digest,
            'severity':detection.get('Severity'),'reason_codes':detection.get('ReasonCodes')}
        with self.lock:
            row=self.db.execute('SELECT sha256 FROM events WHERE sensor=? AND event_id=?',(sensor,event_id)).fetchone()
            if row and row[0]!=digest:raise ValueError('Conflicting event content; previous record preserved')
            if not row:
                # Reject new admission instead of deleting evidence. The exporter
                # retains its checkpoint and retries after capacity is restored.
                usage=sum(p.stat().st_size for p in self.root.iterdir() if p.is_file())
                if usage+len(frame)*8+MAX_FRAME>self.maximum_bytes:raise OSError('Journal capacity exhausted')
                self.db.execute('INSERT INTO events(sensor,event_id,sha256,record) VALUES(?,?,?,?)',(sensor,event_id,digest,json.dumps(record,separators=(',',':'),ensure_ascii=True)));self.db.commit()
            # A storage receipt refers to the durable SQLite commit, not search indexing.
            receipt={'version':1,'event_id':event_id,'payload_sha256':digest,'persisted':True}
            self.export()
            return receipt
    def export(self):
        with self.lock:
            if self.ready is not None and not self.ready():return 0
            rows=self.db.execute('SELECT sequence,record FROM events WHERE exported=0 ORDER BY sequence LIMIT 100').fetchall()
            if not rows:return 0
            for name,projection in [('events',False),('rules',True)]:
                output=self.root/(name+'.jsonl')
                # Keep the compact rule feed on its registered inode. Creating
                # a populated replacement before Wazuh opens it can skip alerts.
                # Overall admission quota still bounds this file and the journal.
                if name=='events' and output.exists() and output.stat().st_size>=self.rotation_bytes:
                    # Unique names, no overwrite and no automatic evidence deletion.
                    import uuid
                    output.rename(self.root/(name+'-'+uuid.uuid4().hex+'.jsonl'))
                with open(output,'ab') as stream:
                    for _,record in rows:
                        if projection:
                            data=json.loads(record);value=data.get('rule_projection')
                            if value is None:raise ValueError('Stored rule projection unavailable; evidence retained')
                            stream.write(json.dumps(value,separators=(',',':'),ensure_ascii=True).encode()+b'\n')
                        else:stream.write(record.encode()+b'\n')
                    stream.flush();os.fsync(stream.fileno())
            self.db.executemany('UPDATE events SET exported=1 WHERE sequence=?',[(row[0],) for row in rows]);self.db.commit()
            return len(rows)
    def close(self):
        with self.lock:self.db.close()

def read_frame(stream):
    length=bytearray()
    while len(length)<=6:
        byte=stream.recv(1)
        if byte==b' ':break
        if not byte or not byte.isdigit():raise ValueError('Octet-counted frame required')
        length.extend(byte)
    else:raise ValueError('Frame prefix too long')
    count=int(length or b'0')
    if not 1<=count<=MAX_FRAME:raise ValueError('Frame too large')
    frame=bytearray()
    while len(frame)<count:
        part=stream.recv(min(8192,count-len(frame)))
        if not part:raise ValueError('Incomplete frame')
        frame.extend(part)
    return bytes(frame)

def configure_tls(context,config):
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    tickets=config.get('tls_session_tickets',True)
    if type(tickets) is not bool:raise ValueError('TLS session ticket setting must be boolean')
    if not tickets:
        context.options|=ssl.OP_NO_TICKET
        context.num_tickets=0
    return context

def serve(config):
    allowed={str(ipaddress.ip_address(ip)) for ip in config['allowed_sources']}
    if not allowed:raise ValueError('At least one authorized source is required')
    if not isinstance(config['port'],int) or not 1<=config['port']<=65535:raise ValueError('Invalid listening port')
    readiness=(lambda:wazuh_ready(config['journal_directory'])) if config.get('require_wazuh_ready',False) else None
    journal=Journal(config['journal_directory'],config.get('maximum_journal_bytes',1024*1024*1024),config.get('rotation_bytes',128*1024*1024),ready=readiness);stop=threading.Event()
    def diagnostic(error,phase='journal-export',tls=None):print(json.dumps({'component':'sequester-receiver','status':'rejected-or-pending','error_type':type(error).__name__,'detail':str(error)[:256],'phase':phase,'tls':tls}),flush=True)
    def drain():
        while not stop.is_set():
            try:
                while not stop.is_set() and journal.export():pass
            except (OSError,ValueError,sqlite3.Error) as error:diagnostic(error)
            stop.wait(2)
    worker=threading.Thread(target=drain,name='sequester-journal-export',daemon=True)
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    context=configure_tls(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),config);context.load_cert_chain(config['certificate'],config['private_key'])
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind((config['bind'],config['port']));listener.listen(16);listener.settimeout(1)
    worker.start()
    try:
        while not stop.is_set():
            try:raw,peer=listener.accept()
            except socket.timeout:continue
            raw.settimeout(8)
            if str(ipaddress.ip_address(peer[0])) not in allowed:raw.close();continue
            phase='tls-handshake';negotiated=None
            try:
                with context.wrap_socket(raw,server_side=True) as stream:
                    negotiated={'protocol':stream.version(),'cipher':stream.cipher()[0]};phase='frame-read';frame=read_frame(stream)
                    phase='journal-admission';receipt=journal.accept(frame,peer[0]);phase='receipt-write';stream.sendall(json.dumps(receipt,separators=(',',':')).encode()+b'\n')
            except (OSError,ValueError,sqlite3.Error) as error:
                raw.close();diagnostic(error,phase,negotiated)
    finally:
        stop.set();listener.close();worker.join(timeout=12)
        if worker.is_alive():raise RuntimeError('Journal exporter did not stop')
        journal.close()
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args();os.umask(0o027)
    serve(json.loads(pathlib.Path(args.config).read_text()))
