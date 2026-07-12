'use strict';

/** Region hosts and FilePicker constants. Read-only config — no secrets. */
const REGIONS = {
  CN: {
    id: 'CN',
    apiHost: process.env.CN_API_HOST || 'h72-ms-prod.netease.com',
    faceFilePickerUploadUrl:
      process.env.CN_FACE_FILEPICKER_URL || 'https://fp.ps.netease.com/h72face/file/new/',
    // Download hosts for face short-code objects (order = fallback order)
    cdnHosts: [
      'h72face-cn.fp.ps.netease.com',
      'h72.fp.ps.netease.com',
      'h72wxj.fp.ps.netease.com',
    ],
    shortPrefix: 'yysls',
    objectKeySuffix: '07', // common; not authoritative for region
  },
  SEA: {
    id: 'SEA',
    apiHost: process.env.GLOBAL_API_HOST || 'h72naxx2gb-ms-prod.easebar.com',
    faceFilePickerUploadUrl:
      process.env.GLOBAL_FACE_FILEPICKER_URL || 'https://fp.ps.easebar.com/h72facesg/file/new/',
    cdnHosts: ['h72sg.fp.ps.easebar.com'],
    shortPrefix: 'wwm',
    objectKeySuffix: '03',
  },
};

REGIONS.GLOBAL = REGIONS.SEA;

const PLAN_TAG_FACE = 1001;
const PLAN_TAG_MAKEUP = 1002;

/** FilePicker object key: 24 hex + 8 alnum + 2 digit region suffix */
const FP_OBJECT_KEY_RE = /^[0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2}$/;

const SHORT_CODE_RE = /^(yysls|wwm)_facedata_R(\d+)_([0-9a-f]{24}[A-Za-z0-9]{8}[0-9]{2})$/i;

/** All allowlisted CDN hosts for short-code download */
function allCdnHosts() {
  return [...new Set([...REGIONS.CN.cdnHosts, ...REGIONS.SEA.cdnHosts])];
}

function cdnHostsForShortPrefix(prefix) {
  const p = String(prefix).toLowerCase();
  if (p === 'yysls') return REGIONS.CN.cdnHosts;
  if (p === 'wwm') return REGIONS.SEA.cdnHosts;
  return [];
}

function regionIdFromShortPrefix(prefix) {
  const p = String(prefix).toLowerCase();
  if (p === 'yysls') return 'CN';
  if (p === 'wwm') return 'GLOBAL';
  return null;
}

module.exports = {
  REGIONS,
  PLAN_TAG_FACE,
  PLAN_TAG_MAKEUP,
  FP_OBJECT_KEY_RE,
  SHORT_CODE_RE,
  allCdnHosts,
  cdnHostsForShortPrefix,
  regionIdFromShortPrefix,
};
