import importlib.util,json,pathlib,sqlite3,tempfile,unittest,os,ssl
spec=importlib.util.spec_from_file_location('receiver',pathlib.Path(__file__).with_name('sequester_receiver.py'));receiver=importlib.util.module_from_spec(spec);spec.loader.exec_module(receiver)
class ReceiverTests(unittest.TestCase):
    def test_tls_default_preserves_session_tickets(self):
        context=receiver.configure_tls(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),{})
        self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertFalse(context.options&ssl.OP_NO_TICKET)
        self.assertGreater(context.num_tickets,0)
    def test_tls_ticket_disable_preserves_protocol_floor(self):
        context=receiver.configure_tls(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),{'tls_session_tickets':False})
        self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.options&ssl.OP_NO_TICKET)
        self.assertEqual(context.num_tickets,0)
    def test_tls_unknown_ticket_setting_rejected(self):
        for value in [None,'false',0,1]:
            with self.assertRaises(ValueError):receiver.configure_tls(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),{'tls_session_tickets':value})
    def setUp(self):self.directory=tempfile.TemporaryDirectory();self.journal=receiver.Journal(self.directory.name)
    def tearDown(self):self.journal.close();self.directory.cleanup()
    def frame(self,**changes):
        event={'EventId':'a'*32,'EndpointId':'b'*32,'Machine':'sensor-01','ForwardedBy':'server-01','ProcessId':4242,'Source':'Windows minifilter','NotificationSuppressed':False};event.update(changes)
        return b'<134>1 2026-10-12T00:00:00Z server-01 RansomFree 42 CANARY - '+json.dumps(event,separators=(',',':')).encode()
    def test_storage_and_identity(self):
        receipt=self.journal.accept(self.frame(),'192.0.2.1');self.assertTrue(receipt['persisted']);self.assertEqual(receipt['event_id'],'a'*32)
        record=json.loads((pathlib.Path(self.directory.name)/'events.jsonl').read_text());self.assertEqual(record['host'],'sensor-01');self.assertEqual(record['forwarded_by'],'server-01');self.assertEqual(record['process_pid'],4242);self.assertFalse(record['notification_suppressed'])
        self.assertEqual(record['sensor_host'],'sensor-01')
    def test_log_only_keeps_evidence(self):
        self.journal.accept(self.frame(NotificationSuppressed=True,Forensics={'Process':{'Owner':None}}),'192.0.2.1');record=json.loads((pathlib.Path(self.directory.name)/'events.jsonl').read_text());self.assertTrue(record['notification_suppressed']);self.assertIsNone(record['evidence']['Forensics']['Process']['Owner'])
    def test_duplicate_and_conflict(self):
        first=self.journal.accept(self.frame(),'192.0.2.1');self.assertEqual(first,self.journal.accept(self.frame(),'192.0.2.1'));self.assertEqual(self.journal.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
        with self.assertRaises(ValueError):self.journal.accept(self.frame(ProcessId=4243),'192.0.2.1')
    def test_restart_and_unexported_recovery(self):
        self.journal.accept(self.frame(),'192.0.2.1');self.journal.db.execute('UPDATE events SET exported=0');self.journal.db.commit();self.journal.close();self.journal=receiver.Journal(self.directory.name);self.journal.export();rows=(pathlib.Path(self.directory.name)/'events.jsonl').read_text().splitlines();self.assertEqual(len(rows),2);self.assertEqual(json.loads(rows[0])['document_id'],json.loads(rows[1])['document_id'])
    def test_malformed_and_size(self):
        for frame in [b'{}',b'RansomFree: []',self.frame(EventId='invalid'),b'x'*(receiver.MAX_FRAME+1)]:
            with self.assertRaises(ValueError):self.journal.accept(frame,'192.0.2.1')
    def test_enrichment_is_log(self):
        self.journal.accept(self.frame(Source='Forensic enrichment'),'192.0.2.1');self.assertEqual(json.loads((pathlib.Path(self.directory.name)/'events.jsonl').read_text())['record_kind'],'evidence')
    def test_malformed_nested_evidence(self):
        for fields in [{'Forensics':False},{'Forensics':{'ActorExecutable':[]}},{'Trust':0},{'Trust':{'Actor':'not an object'}}]:
            with self.assertRaises(ValueError):self.journal.accept(self.frame(**fields),'192.0.2.1')
        self.assertEqual(self.journal.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
    def test_exact_producer(self):
        for value in [self.frame().replace(b' RansomFree ',b' FakeRansomFree '),self.frame().replace(b'<134>1 ',b'<134>9 '),self.frame(EndpointId='sensor\nforged')]:
            with self.assertRaises(ValueError):self.journal.accept(value,'192.0.2.1')
    def test_capacity_retains_prior_evidence(self):
        first=self.journal.accept(self.frame(),'192.0.2.1');self.journal.maximum_bytes=1
        self.assertEqual(first,self.journal.accept(self.frame(),'192.0.2.1'))
        with self.assertRaises(OSError):self.journal.accept(self.frame(EventId='c'*32),'192.0.2.1')
        self.assertEqual(self.journal.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
    def test_rotation_keeps_every_record(self):
        self.journal.rotation_bytes=1
        self.journal.accept(self.frame(),'192.0.2.1');self.journal.accept(self.frame(EventId='c'*32),'192.0.2.1')
        paths=list(pathlib.Path(self.directory.name).glob('events*.jsonl'));self.assertEqual(len(paths),2)
        rows=[json.loads(line) for path in paths for line in path.read_text().splitlines()]
        self.assertEqual({r['event_id'] for r in rows},{'a'*32,'c'*32})
    def test_drain_backlog_without_new_admission(self):
        self.journal.accept(self.frame(),'192.0.2.1')
        self.journal.db.execute('UPDATE events SET exported=0');self.journal.db.commit()
        self.assertEqual(self.journal.export(),1);self.assertEqual(self.journal.export(),0)
    def test_invalid_capacity(self):
        with self.assertRaises(ValueError):receiver.Journal(self.directory.name,maximum_bytes=0)
    def test_rule_feed_has_original_identity_without_raw_evidence(self):
        self.journal.accept(self.frame(Forensics={'Process':{'InstanceId':'d'*64,'Owner':{'Sid':'S-1-5-21-1-2-3-1000'},'EffectiveThreadContext':{'Sid':'S-1-5-21-1-2-3-2000'},'Impersonating':True}},NotificationSuppressed=True),'192.0.2.1')
        rule=json.loads((pathlib.Path(self.directory.name)/'rules.jsonl').read_text())
        self.assertEqual(rule['process_owner_sid'],'S-1-5-21-1-2-3-1000');self.assertEqual(rule['effective_sid'],'S-1-5-21-1-2-3-2000');self.assertTrue(rule['notification_suppressed']);self.assertEqual(rule['host'],'sensor-01');self.assertEqual(rule['forwarded_by'],'server-01');self.assertNotIn('evidence',rule)
    def test_collector_startup_retains_delivery_until_ready(self):
        ready=False;self.journal.ready=lambda:ready
        receipt=self.journal.accept(self.frame(),'192.0.2.1');self.assertTrue(receipt['persisted'])
        self.assertEqual((pathlib.Path(self.directory.name)/'rules.jsonl').read_bytes(),b'');self.assertEqual(self.journal.db.execute('SELECT exported FROM events').fetchone()[0],0)
        ready=True;self.assertEqual(self.journal.export(),1);self.assertEqual(len((pathlib.Path(self.directory.name)/'rules.jsonl').read_text().splitlines()),1)
    def test_missing_or_stale_collector_state_is_not_ready(self):
        self.assertFalse(receiver.wazuh_ready(self.directory.name,self.directory.name,self.directory.name))
    @unittest.skipUnless(hasattr(os,'sysconf'),'Actual Linux process clock configuration is required')
    def test_readiness_ignores_old_state_after_collector_restart(self):
        root=pathlib.Path(self.directory.name);state=root/'var/run/wazuh-logcollector.state';state.parent.mkdir(parents=True)
        proc=root/'proc';(proc/'123').mkdir(parents=True);(proc/'uptime').write_text('1000 0');(proc/'123/comm').write_text('wazuh-logcollec')
        fields=['S']+['0']*18+[str(950*os.sysconf('SC_CLK_TCK'))];(proc/'123/stat').write_text('123 (wazuh-logcollector) '+' '.join(fields))
        state.write_text(json.dumps({'global':{'files':[{'location':str(root/'rules.jsonl')}]}}));os.utime(state,(1940,1940))
        self.assertFalse(receiver.wazuh_ready(str(root),str(root),str(proc),now=2000))
        os.utime(state,(1980,1980));self.assertTrue(receiver.wazuh_ready(str(root),str(root),str(proc),now=2000))
        os.utime(state,(1800,1800));self.assertFalse(receiver.wazuh_ready(str(root),str(root),str(proc),now=2000))
if __name__=='__main__':unittest.main()
