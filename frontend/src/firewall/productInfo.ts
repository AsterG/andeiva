import { ApiError } from './api.js';

export type ProductInfo = {
  product: 'ANDEIVA Security Gateway';
  version?: string;
  channel: 'development' | 'experimental';
  update_status: 'unavailable';
};

export type ProductInfoState = { state: 'loading' } | { state: 'unavailable' } | { state: 'ready'; info: ProductInfo };

export function productInfoResponse(value: unknown): ProductInfo {
  const invalid = () => { throw new ApiError('ANDEIVA_RESPONSE_INVALID'); };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const info = value as Record<string, unknown>;
  const fields = Object.keys(info);
  if (fields.some((key) => !['product', 'version', 'channel', 'update_status'].includes(key)) || info.product !== 'ANDEIVA Security Gateway' || info.update_status !== 'unavailable') return invalid();
  if (info.channel === 'development' && !Object.hasOwn(info, 'version') && fields.length === 3) return { product: info.product, channel: info.channel, update_status: info.update_status };
  if (info.channel === 'experimental' && fields.length === 4 && typeof info.version === 'string' && info.version.length <= 64 && /^0\.1\.0~alpha[1-9][0-9]*$/.exec(info.version)?.[0] === info.version) return { product: info.product, version: info.version, channel: info.channel, update_status: info.update_status };
  return invalid();
}
