export type Identity={ip:string;mac:string};
export const normalizeMac=(mac:string)=>mac.replace(/-/g,':').toLowerCase();
export function findKnownDevice<T extends Identity>(previous:T[],next:Identity):T|undefined{
 return previous.find(device=>device.ip===next.ip&&normalizeMac(device.mac)===normalizeMac(next.mac));
}
