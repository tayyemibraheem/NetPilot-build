// Verify Tauri's public Minisign signature with Node's built-in Ed25519 implementation.
// Reference format: https://jedisct1.github.io/minisign/#signature-format
import {readFileSync} from 'node:fs';
import {createHash,createPublicKey,verify} from 'node:crypto';
const [file,sigFile]=process.argv.slice(2);
if(!file||!sigFile)throw Error('Usage: node scripts/verify-update.mjs installer.exe installer.exe.sig');
const config=JSON.parse(readFileSync('src-tauri/tauri.conf.json','utf8'));
const decode=text=>text.trim().startsWith('untrusted comment:')?text.trim():Buffer.from(text.trim(),'base64').toString('utf8').trim();
const publicLines=decode(config.plugins.updater.pubkey).split(/\r?\n/);
const signatureLines=decode(readFileSync(sigFile,'utf8')).split(/\r?\n/);
const pub=Buffer.from(publicLines[1],'base64'),packet=Buffer.from(signatureLines[1],'base64');
if(pub.length!==42||packet.length!==74||pub.subarray(0,2).toString()!=='Ed'||packet.subarray(0,2).toString()!=='ED')throw Error('Unexpected Minisign format; prehashed Ed25519 required');
if(!pub.subarray(2,10).equals(packet.subarray(2,10)))throw Error('Signing key identity mismatch');
const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),pub.subarray(10)]),format:'der',type:'spki'});
const signature=packet.subarray(10),bytes=readFileSync(file);
const digest=input=>createHash('blake2b512').update(input).digest();
if(!verify(null,digest(bytes),key,signature))throw Error('Installer signature verification failed');
const prefix='trusted comment: ';
if(!signatureLines[2]?.startsWith(prefix))throw Error('Missing signed trusted comment');
const comment=signatureLines[2].slice(prefix.length),globalSignature=Buffer.from(signatureLines[3],'base64');
if(!verify(null,Buffer.concat([signature,Buffer.from(comment)]),key,globalSignature))throw Error('Signed metadata verification failed');
// The CLI binds the version in this trusted comment; the native updater requires it too.
const version=comment.match(/(?:^|\s)version:([^\s]+)/)?.[1];
if(version!==config.version)throw Error('Signed version does not match application version');
const corrupt=Buffer.from(bytes);corrupt[0]^=1;
if(verify(null,digest(corrupt),key,signature))throw Error('Corrupted payload incorrectly accepted');
if(verify(null,Buffer.concat([signature,Buffer.from(comment+'-tampered')]),key,globalSignature))throw Error('Tampered metadata incorrectly accepted');
console.log(`Verified Ed25519 signature, signed version ${version}, and rejection of tampered payload/metadata.`);
