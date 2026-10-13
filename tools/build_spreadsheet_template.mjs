import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
await fs.mkdir(path.join(root,'Assets'),{recursive:true});
await fs.mkdir(path.join(root,'test-results','formats'),{recursive:true});
const wb=Workbook.create();
const sheet=wb.worksheets.add('Recovery register');
sheet.showGridLines=false;
sheet.getRange('A1:D10').format.font={name:'Arial',size:11};
sheet.getRange('A1:D10').format.rowHeight=24;
sheet.getRange('A1:D10').format.verticalAlignment='center';
sheet.getRange('A1:A10').format.columnWidth=28;
sheet.getRange('B1:B10').format.columnWidth=26;
sheet.getRange('C1:C10').format.columnWidth=26;
sheet.getRange('D1:D10').format.columnWidth=16;
sheet.getRange('A2').values=[['Recovery register']];
sheet.getRange('A2').format.font={name:'Arial',size:16,bold:true};
sheet.getRange('A4:D4').values=[['Reference','Record group','Custodian','Copies']];
sheet.getRange('A4:D4').format={fill:'#24364B',font:{name:'Arial',size:11,bold:true,color:'#FFFFFF'},horizontalAlignment:'center'};
sheet.getRange('A5:D7').values=[
    ['DEMO-RECOVERY-001','Operations archive','Example Operations',2],
    ['DEMO-RECOVERY-002','Recovery records','Example Operations',1],
    ['DEMO-RECOVERY-003','Retention schedule','Example Operations',1]
];
sheet.getRange('A6:D6').format.fill='#F0F3F7';
sheet.getRange('D5:D7').setNumberFormat('0');
sheet.getRange('D5:D7').format.horizontalAlignment='right';
sheet.getRange('A9').values=[['Synthetic security canary. No real credentials or personal data.']];
sheet.getRange('A9').format.font={name:'Arial',size:10,italic:true,color:'#555555'};
wb.recalculate();
console.log((await wb.inspect({kind:'table',range:'Recovery register!A4:D7',include:'values',tableMaxRows:4,tableMaxCols:4})).ndjson);
const preview=await wb.render({sheetName:sheet.name,range:'A1:D10',scale:1.5,format:'png'});
await fs.writeFile(path.join(root,'test-results','formats','xlsx.png'),new Uint8Array(await preview.arrayBuffer()));
await (await SpreadsheetFile.exportXlsx(wb)).save(path.join(root,'Assets','canary.xlsx'));
console.log('Created XLSX template');
