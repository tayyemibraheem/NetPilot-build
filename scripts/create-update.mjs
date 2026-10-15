import {readFileSync,writeFileSync} from 'node:fs';
import {basename} from 'node:path';
const [file,sigFile,tag]=process.argv.slice(2);
const version=JSON.parse(readFileSync('src-tauri/tauri.conf.json','utf8')).version;
if(!/^\d+\.\d+\.\d+$/.test(version)||!tag)throw Error('Expected a numeric app version and immutable release tag');
const url=`https://github.com/tayyemibraheem/NetPilot-build/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(basename(file))}`;
const platform={url,signature:readFileSync(sigFile,'utf8').trim()};
writeFileSync('latest.json',JSON.stringify({version,notes:'NetPilot update: persistent original errors and diagnostic report, measured traffic rates, names and labels, Npcap setup detection, and signed safe updates. Windows network behavior still requires validation.',pub_date:new Date().toISOString(),platforms:{'windows-x86_64':platform,'windows-x86_64-nsis':platform},source_commit:process.env.GITHUB_SHA??'local-signature-test'},null,2)+'\n');
