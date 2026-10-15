import test from 'node:test';
import assert from 'node:assert/strict';
import {findKnownDevice} from './device-state.ts';
test('cache and ARP MAC spelling changes preserve the same selected owned identity',()=>{
 const owned={ip:'192.168.1.3',mac:'02-AA-BB-CC-DD-03',selected:true,blocked:true,label:'My phone'};
 assert.equal(findKnownDevice([owned],{ip:owned.ip,mac:'02:aa:bb:cc:dd:03'}),owned);
});
test('an IP reused by another MAC cannot inherit selection, blocking or the old label',()=>{
 const owned={ip:'192.168.1.3',mac:'02:aa:bb:cc:dd:03',selected:true,blocked:true,label:'My phone'};
 assert.equal(findKnownDevice([owned],{ip:owned.ip,mac:'02:aa:bb:cc:dd:04'}),undefined);
 assert.equal(findKnownDevice([owned],{ip:'192.168.1.4',mac:owned.mac}),undefined);
});
