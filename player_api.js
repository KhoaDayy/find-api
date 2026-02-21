const express = require('express');
const axios = require('axios');
const fs = require('fs');
const https = require('https');
const cors = require('cors');
const msgpack = require('msgpack-lite');
const dns = require('dns');

const app = express();
app.use(cors());
app.use(express.json());

// --- CẤU HÌNH ---
const SERVERS = {
    SEA: "h72naxx2gb-ms-prod.easebar.com",
    CN: "h72-ms-prod.netease.com",
};

const HOST_LEGACY = "https://h72-ms-prod.netease.com"; // Legacy cho /convert
const SESSION_FILE = String.raw`C:\Users\AD\Desktop\find api\session.txt`;
const SESSION_FILE_HOOK = String.raw`C:\Users\AD\Desktop\find api\HOOK\session.txt`;
const SESSION_KEY_DEFAULT = "aZI1T+6l/ryIB0pD";

const HEADERS_LEGACY = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; Pixel 6 Build/SP2A.220305.013.A3)",
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive"
};

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// --- DNS RESOLVE CACHE (bypass hosts file redirect) ---
const dnsCache = {};
const googleDns = new dns.Resolver();
googleDns.setServers(['8.8.8.8', '8.8.4.4']);

async function resolveHost(hostname) {
    if (dnsCache[hostname] && (Date.now() - dnsCache[hostname].ts < 300000)) {
        return dnsCache[hostname].ip;
    }
    try {
        const addresses = await new Promise((resolve, reject) => {
            googleDns.resolve4(hostname, (err, addrs) => {
                if (err) reject(err); else resolve(addrs);
            });
        });
        const ip = addresses[0];
        dnsCache[hostname] = { ip, ts: Date.now() };
        console.log(`\x1b[35m[DNS]\x1b[0m ${hostname} -> ${ip}`);
        return ip;
    } catch (e) {
        console.log(`\x1b[35m[DNS]\x1b[0m Resolve failed for ${hostname}: ${e.message}, using hostname directly`);
        return hostname;
    }
}

// --- SCHOOL MAPPING (phải match SECT_INFO trong player-lookup.js) ---
const SCHOOL_NAMES = {
    1: "Silver Needle",
    2: "The Masked Troupe",
    3: "Emei",
    4: "Tangmen",
    5: "Five Immortals",
    6: "Scholar",
    7: "Beggar",
    8: "Flower",
    9: "Free",
    10: "Wudu",
    11: "Shaolin",
    12: "Shaolin",
    13: "Scholar",
};

// --- HELPER FUNCTIONS ---

function get_session_key() {
    // Try multiple session file locations
    for (const file of [SESSION_FILE, SESSION_FILE_HOOK]) {
        try {
            if (fs.existsSync(file)) {
                const key = fs.readFileSync(file, 'utf8').trim();
                if (key.length > 5) return key;
            }
        } catch (e) { }
    }
    return SESSION_KEY_DEFAULT;
}

/**
 * Legacy call (JSON) - dùng cho /convert
 */
async function call_uwsgi(op, data) {
    const url = `${HOST_LEGACY}${op}`;
    const session_key = get_session_key();
    const params = { session: session_key };

    try {
        console.log(`\x1b[36m[API]\x1b[0m CALL ${op} (Key: ${session_key.substring(0, 5)}...)`);
        const response = await axios.post(url, data, {
            params: params,
            headers: HEADERS_LEGACY,
            httpsAgent: httpsAgent,
            timeout: 5000,
            validateStatus: () => true
        });

        if (response.status === 200) {
            const rj = response.data;
            if (!rj || (typeof rj === 'object' && Object.keys(rj).length === 0)) {
                return null;
            }
            return rj;
        }
        return null;
    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Error: ${e.message}`);
        return null;
    }
}

/**
 * Msgpack call - dùng cho player lookup
 */
async function msgpack_request(host, endpoint, payload) {
    const body = msgpack.encode(payload);
    const session = get_session_key();
    const realIp = await resolveHost(host);

    return new Promise((resolve, reject) => {
        const options = {
            hostname: realIp,
            path: `${endpoint}?session=${encodeURIComponent(session)}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/msgpack',
                'Content-Length': body.length,
                'h72-ms-uid': session,
                'Host': host
            },
            servername: host,
            agent: httpsAgent,
            timeout: 8000
        };

        const req = https.request(options, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                try {
                    resolve(msgpack.decode(buf));
                } catch (e) {
                    try {
                        resolve(JSON.parse(buf.toString('utf8')));
                    } catch (e2) {
                        reject(new Error(`Decode failed: ${buf.toString('utf8').substring(0, 200)}`));
                    }
                }
            });
        });

        req.on('error', e => reject(e));
        req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
        req.write(body);
        req.end();
    });
}

/**
 * Msgpack call WITH session
 */
async function msgpack_request_with_session(host, endpoint, payload, customBuffer = null) {
    const body = customBuffer || msgpack.encode(payload);
    const session = get_session_key();
    const path = `${endpoint}?session=${encodeURIComponent(session)}`;
    const realIp = await resolveHost(host);

    return new Promise((resolve, reject) => {
        const options = {
            hostname: realIp,
            path: path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/msgpack',
                'Content-Length': body.length,
                'h72-ms-uid': session,
                'Host': host
            },
            servername: host,
            agent: httpsAgent,
            timeout: 8000
        };

        const req = https.request(options, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                if (res.statusCode !== 200) {
                    console.log(`\x1b[31m[ERR]\x1b[0m ${endpoint} returned ${res.statusCode}`);
                    resolve(null);
                    return;
                }
                try {
                    resolve(msgpack.decode(buf));
                } catch (e) {
                    console.log(`\x1b[31m[ERR]\x1b[0m msgpack decode error for ${endpoint}: ${e.message}`);
                    console.log(`\x1b[31m[ERR]\x1b[0m Response buf hex (first 100): ${buf.toString('hex').substring(0, 100)}`);
                    console.log(`\x1b[31m[ERR]\x1b[0m Response text (first 200): ${buf.toString('utf8').substring(0, 200)}`);
                    resolve(null);
                }
            });
        });

        req.on('error', (e) => { console.log(`\x1b[31m[ERR]\x1b[0m Request error for ${endpoint}: ${e.message}`); resolve(null); });
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.write(body);
        req.end();
    });
}

/**
 * Fetch extra player data from redis_player/get_players_info
 * Returns enriched fields: name_card (sign, badges), head, mentor (is_master), birthday
 */
async function fetchExtraPlayerData(host, pid, hostnum) {
    if (!pid || !hostnum) return null;

    try {
        const isCN = Number(hostnum) < 10400;
        const requestedFields = ["base", "head", "name_card", "title_prop", "school", "birthday", "mentor", "disease", "club", "gameplay_trail", "settings"];
        if (isCN) {
            requestedFields.push("story_prop", "coop_score", "lunjian", "common_score_data", "ququs");
        }

        const pidsBuf = msgpack.encode([pid]);
        const fieldsBuf = msgpack.encode(requestedFields);

        // Manual Map to force integer key for hostnum
        const numBuf = Buffer.alloc(3);
        numBuf[0] = 0xcd; // uint16
        numBuf.writeUInt16BE(Number(hostnum), 1);

        const mapBuf = Buffer.concat([Buffer.from([0x81]), numBuf, pidsBuf]);
        const customBuffer = Buffer.concat([
            Buffer.from([0x82]),
            msgpack.encode('hostnum2pids'),
            mapBuf,
            msgpack.encode('fields'),
            fieldsBuf
        ]);

        const data = await msgpack_request_with_session(host, '/flk/redis_player/get_players_info', null, customBuffer);
        require('fs').writeFileSync('temp_out.json', JSON.stringify(data, null, 2));

        const { encode: encodeMap } = require('@msgpack/msgpack');
        if (!data || typeof data !== 'object') return null;

        // The python game server returns { code: 0, result: { [pid]: { ...data... } } }
        const resultDict = data.result || data;
        const playerData = resultDict[pid];
        if (!playerData) return null;

        console.log(`\x1b[36m[API]\x1b[0m Extra data fetched for ${pid}: ${Object.keys(playerData).join(', ')}`);

        // Fetch club name if club exists
        if (playerData.club && playerData.club.club_id) {
            try {
                const clubMap = {
                    club_id: playerData.club.club_id,
                    uid: get_session_key(),
                    field_info: { base: [] },
                    hostnum: Number(playerData.club.hostnum)
                };
                const cData = await msgpack_request_with_session(host, '/flk/club_service/get_club_info', clubMap);
                const cResult = cData?.result?.base || cData?.base;
                if (cResult && cResult.name) {
                    playerData.club.club_name = cResult.name;
                    console.log(`\x1b[36m[API]\x1b[0m Found Club Name: ${cResult.name}`);
                }
            } catch (ce) {
                console.log(`\x1b[31m[ERR]\x1b[0m Club name fetch failed: ${ce.message}`);
            }
        }

        return playerData;
    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Extra data fetch failed: ${e.message}`);
        return null;
    }
}

/**
 * Fetch full profile data using player_service/hget_data
 * This is the exact method triggered when looking at a player profile in-game.
 */
async function fetchPlayerProfile(host, puid, hostnum) {
    if (!puid || !hostnum) return null;

    try {
        const payload = {
            uid: get_session_key(),
            puid: puid,
            hostnum: Number(hostnum),
            keys: ['player_local_data_npc_stuff'],
            tag: 'player'
        };

        const data = await msgpack_request_with_session(host, '/player_service/hget_data', payload);

        if (data) {
            console.log(`\x1b[36m[API]\x1b[0m Full Profile data fetched for ${puid}`);
            return data;
        }
        return null;
    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Full Profile fetch failed: ${e.message}`);
        return null;
    }
}

let last_cover_img = null;

/**
 * Fetch fashion data including shot_img from fashion_service/get_fashion_plan
 * shot_img is NOT in redis_player - it's only in fashion_service!
 */
async function fetchFashionData(host, pid, hostnum) {
    if (!pid || !hostnum) return null;

    try {
        const planPayload = { pid: String(pid), hostnum: Number(hostnum) };
        const planEndpoint = '/flk/fashion_service/get_fashion_plan';

        const planData = await msgpack_request_with_session(host, planEndpoint, planPayload);
        const scoreData = await msgpack_request_with_session(host, '/fashion_service/get_fashion_score', planPayload);

        const result = {
            shot_img: null,
            cover_img: null,
            fashion_score: null
        };

        if (planData && planData.result) {
            result.shot_img = planData.result.shot_img || null;
            result.cover_img = planData.result.cover_img || null;

            if (result.cover_img) {
                last_cover_img = result.cover_img;
            } else if (last_cover_img) {
                result.cover_img = last_cover_img;
                console.log(`\x1b[36m[API]\x1b[0m Fallback: Using last known cover_img`);
            }

            console.log(`\x1b[36m[API]\x1b[0m Fashion plan: shot_img=${result.shot_img ? 'yes' : 'no'}, cover_img=${result.cover_img ? 'yes' : 'no'}`);
        } else {
            console.log(`\x1b[36m[API]\x1b[0m Fashion plan: failed to fetch or missing result`);
        }

        if (scoreData && scoreData.result) {
            result.fashion_score = Number(scoreData.result) || null;
            console.log(`\x1b[36m[API]\x1b[0m Fashion score: ${result.fashion_score}`);
        }

        return result;
    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Fashion fetch failed: ${e.message}`);
        return null;
    }
}

/**
 * Format player data theo cấu trúc chuẩn
 * @param {object} raw - Response từ find_people endpoint
 * @param {object} extra - Optional extra data từ redis_player/get_players_info
 */
function formatPlayerData(raw, extra) {
    if (!raw || !raw.result || Object.keys(raw.result).length === 0) {
        return null;
    }

    const r = raw.result;
    const base = r.base || {};

    // Extra data from redis_player (if available)
    const extraBase = extra?.base || {};
    const nameCard = extra?.name_card || {};
    const head = extra?.head || {};
    const mentor = extra?.mentor || {};
    const birthday = extra?.birthday || {};
    const school = extra?.school || {};
    const disease = extra?.disease || {};

    // Fashion data from fashion_service (separate parameter)
    const fashionData = extra?._fashion || {};
    const profileData = extra?._profile || {};

    return {
        oversea_language_choose: base.oversea_language_choose || null,
        level: extraBase.level || base.level || 0,
        max_xiuwei_kungfu: extraBase.max_xiuwei_kungfu || base.max_xiuwei_kungfu || 0,
        body_type: extraBase.body_type ?? base.body_type ?? null,
        create_time: extraBase.create_time || base.create_time || null,
        ly_stage_name: extraBase.ly_stage_name || base.ly_stage_name || null,
        server_hostnum: base.server_hostnum || r.hostnum || null,
        nickname: extraBase.nickname || base.nickname || "Unknown",
        social_mode: extraBase.social_mode ?? base.social_mode ?? null,
        oversea_tag: base.oversea_tag || null,
        device_name: base.device_name || null,
        chuyan_flag: extraBase.chuyan_flag ?? base.chuyan_flag ?? 0,
        login_time: extraBase.login_time || base.login_time || null,
        school: extraBase.school || base.school || 0,
        number_id: extraBase.number_id || base.number_id || null,
        online_time: extraBase.online_time || base.online_time || 0,
        logout_time: extraBase.logout_time || base.logout_time || null,
        school_name: SCHOOL_NAMES[extraBase.school || base.school] || "Unknown",
        hide_school: extraBase.hide_school ?? base.hide_school ?? null,
        is_online: extraBase.is_online ?? base.is_online ?? null,

        // shot_img from fashion_service/get_fashion_plan
        shot_img: fashionData.shot_img || null,
        cover_img: fashionData.cover_img || null,
        fashion_score: fashionData.fashion_score || null,

        // Disease from redis_player
        has_disease: disease.has_disease_flag ? true : (base.has_disease || false),

        // Other fields from find_people base
        solo_level: base.solo_level || null,
        solo_max_level: base.solo_max_level || null,

        // From name_card (enriched via redis_player)
        sign: nameCard.sign || base.sign || null,
        name_card_bg: nameCard.bg || null,
        show_badges: nameCard.show_badges || null,

        // From head (enriched via redis_player)
        head_icon: head.role_icon || null,
        head_icon_res: head.role_icon_res || null,
        head_frame: head.head || null,

        // From mentor (enriched via redis_player)
        is_master: mentor.is_master ? true : (base.is_master || false),
        master_id: mentor.master_id || null,
        students_count: mentor.students?.pids?.length || 0,

        // From birthday
        birthday_month: birthday.month || null,
        birthday_day: birthday.day || null,

        // IDs
        pid: r.id || null,
        hostnum: r.hostnum || null,

        // Full raw profiles
        _raw_profile: profileData,
        _redis_player: extra, // Expose raw redis_player data!
    };
}

// --- ENDPOINTS ---

/**
 * GET /lookup?id=NUMBER_ID&server=SEA|CN
 * GET /lookup?name=NICKNAME&server=SEA|CN
 * Tra cứu thông tin player theo number_id HOẶC nickname.
 * - Nếu có server: Tìm trên server đó.
 * - Nếu KHÔNG có server: Tự động tìm trên TẤT CẢ server (trả về kết quả đầu tiên).
 */
app.get('/lookup', async (req, res) => {
    const numberId = req.query.id;
    const nickname = req.query.name;
    const serverParam = req.query.server;

    if (!numberId && !nickname) {
        return res.status(400).json({ error: "Missing parameter: use 'id' (number_id) or 'name' (nickname)" });
    }

    // Xác định endpoint và payload tương ứng
    const isNameSearch = !!nickname && !numberId;
    const endpoint = isNameSearch ? '/flk/find_people/by_nickname' : '/flk/find_people/by_number_id';
    const payload = isNameSearch
        ? { nickname: String(nickname) }
        : { number_id: String(numberId), force_search: false };

    const searchKey = isNameSearch ? nickname : numberId;

    try {
        // CASE 1: Tìm trên server cụ thể
        if (serverParam) {
            const server = serverParam.toUpperCase();
            const host = SERVERS[server];
            if (!host) {
                return res.status(400).json({ error: `Invalid server: ${server}. Use SEA or CN.` });
            }

            console.log(`\x1b[36m[API]\x1b[0m LOOKUP ${isNameSearch ? 'name' : 'id'}="${searchKey}" on ${server} via ${endpoint}`);

            const raw = await msgpack_request(host, endpoint, payload);
            const basicData = formatPlayerData(raw);
            if (!basicData) {
                return res.json({ code: 0, result: null, msg: "Player not found", raw_code: raw?.code });
            }

            // Enrich with extra data from redis_player + fashion_service (parallel)
            const hn = basicData.hostnum || raw.result?.hostnum;
            const [extra, fashionData, profileData] = await Promise.all([
                fetchExtraPlayerData(host, basicData.pid, hn),
                fetchFashionData(host, basicData.pid, hn),
                fetchPlayerProfile(host, basicData.pid, hn)
            ]);
            if (extra) extra._fashion = fashionData || {};
            if (extra) extra._profile = profileData || {};
            const formatted = formatPlayerData(raw, extra || { _fashion: fashionData || {}, _profile: profileData || {} });
            return res.json({ server: server, ...formatted });
        }

        // CASE 2: Auto-search tất cả server (Parallel)
        console.log(`\x1b[36m[API]\x1b[0m AUTO-LOOKUP ${isNameSearch ? 'name' : 'id'}="${searchKey}" on ALL servers`);

        const firstFound = await Promise.any(
            Object.entries(SERVERS).map(async ([name, host]) => {
                const raw = await msgpack_request(host, endpoint, payload);
                const basicData = formatPlayerData(raw);
                if (!basicData) throw new Error("Not found");

                // Enrich with extra data + fashion (parallel)
                const hn = basicData.hostnum || raw.result?.hostnum;
                const [extra, fashionData, profileData] = await Promise.all([
                    fetchExtraPlayerData(host, basicData.pid, hn),
                    fetchFashionData(host, basicData.pid, hn),
                    fetchPlayerProfile(host, basicData.pid, hn)
                ]);
                if (extra) extra._fashion = fashionData || {};
                if (extra) extra._profile = profileData || {};
                const formatted = formatPlayerData(raw, extra || { _fashion: fashionData || {}, _profile: profileData || {} });
                return { server: name, ...formatted };
            })
        ).catch(() => null);

        // Lấy kết quả đầu tiên tìm được
        if (firstFound) {
            console.log(`\x1b[36m[API]\x1b[0m Found on ${firstFound.server}: ${firstFound.nickname}`);
            return res.json(firstFound);
        }

        // Không tìm thấy
        return res.json({ code: 0, result: null, msg: "Player not found on any server" });

    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Lookup Error: ${e.message}`);
        return res.status(500).json({ error: e.message });
    }
});

/**
 * GET /id?keyword=KEYWORD
 * Bot endpoint: tìm kiếm player theo NUMBER_ID (số) hoặc NICKNAME (tên).
 * - Keyword là số  → tìm bằng /flk/find_people/by_number_id
 * - Keyword là tên → tìm bằng /flk/find_people/by_nickname (✅ đã hoạt động!)
 */
app.get('/id', async (req, res) => {
    const keyword = req.query.keyword;
    if (!keyword) return res.status(400).json({ error: "Missing 'keyword'" });

    // Numeric → tìm bằng number_id
    if (/^\d+$/.test(keyword)) {
        return res.redirect(`/lookup?id=${encodeURIComponent(keyword)}`);
    }

    // Tên (nickname) → tìm bằng by_nickname trên TẤT CẢ server
    return res.redirect(`/lookup?name=${encodeURIComponent(keyword)}`);
});

/**
 * GET /fashion?pid=PID&hostnum=HOSTNUM&server=SEA|CN
 * Gọi trực tiếp endpoint get_fashion_plan mà KHÔNG cần qua bước find_people
 */
app.get('/fashion', async (req, res) => {
    const pid = req.query.pid;
    const hostnum = req.query.hostnum;
    let serverParam = req.query.server || "CN"; // Default CN

    if (!pid || !hostnum) {
        return res.status(400).json({ error: "Missing 'pid' or 'hostnum'" });
    }

    const server = serverParam.toUpperCase();
    const host = SERVERS[server];
    if (!host) {
        return res.status(400).json({ error: `Invalid server: ${server}. Use SEA or CN.` });
    }

    try {
        console.log(`\x1b[36m[API]\x1b[0m FASHION LOOKUP pid="${pid}" hostnum="${hostnum}" on ${server}`);
        const planPayload = { pid: String(pid), hostnum: Number(hostnum) };

        // 1. Get raw fashion plan directly without extra mapping filtering
        const raw_plan = await msgpack_request_with_session(host, '/flk/fashion_service/get_fashion_plan', planPayload);
        const scoreData = await msgpack_request_with_session(host, '/fashion_service/get_fashion_score', planPayload);

        return res.json({
            server: server,
            pid: pid,
            hostnum: hostnum,
            fashion_plan: raw_plan,
            fashion_score: scoreData
        });
    } catch (e) {
        console.log(`\x1b[31m[ERR]\x1b[0m Fashion Error: ${e.message}`);
        return res.status(500).json({ error: e.message });
    }
});



// ---------------------------------------------------------
// 4. API Tra cứu danh sách Bang hội (GET /club_search)
//    ?name=TÊN_BANG&server=SEA (default SEA)
//    Returns list of guilds with detailed info
// ---------------------------------------------------------
app.get('/club_search', async (req, res) => {
    const clubName = req.query.name;
    const serverParam = req.query.server || 'SEA';

    if (!clubName) {
        return res.status(400).json({ error: "Missing name (e.g., ?name=Suri&server=SEA)" });
    }

    const server = serverParam.toUpperCase();
    const host = SERVERS[server];
    if (!host) {
        return res.status(400).json({ error: `Invalid server: ${server}` });
    }

    try {
        console.log(`\x1b[36m[API]\x1b[0m SEARCH CLUB name="${clubName}" on ${server}`);
        const sessionKey = get_session_key();
        const searchMap = {
            group_number: 10001,
            uid: sessionKey,
            limit: 20,
            start: 0,
            club_name: String(clubName)
        };

        const data = await msgpack_request_with_session(host, '/flk/club_service/get_club_by_name', searchMap);

        if (!data || data.code !== 0) {
            return res.json({ error: "Search failed or session error", raw: data });
        }

        const rawResults = data.result?.results || [];
        console.log(`\x1b[36m[API]\x1b[0m Found ${rawResults.length} raw results`);

        if (rawResults.length === 0) {
            return res.json({ server, keyword: clubName, results: [], count: 0 });
        }

        // Fetch detailed info for each guild (parallel, max 10)
        const detailPromises = rawResults.slice(0, 10).map(async (item) => {
            try {
                const infoMap = {
                    club_id: item.club_id,
                    uid: sessionKey,
                    field_info: { base: [], members: [] },
                    hostnum: Number(item.hostnum)
                };
                const info = await msgpack_request_with_session(host, '/flk/club_service/get_club_info', infoMap);
                const base = info?.result?.base || info?.base || {};
                const members = info?.result?.members || info?.members || {};
                return {
                    club_id: item.club_id,
                    hostnum: item.hostnum,
                    name: base.name || "???",
                    level: base.level || 0,
                    liveness: base.liveness || 0,
                    fame: base.fame || 0,
                    fund: base.fund || 0,
                    member_num: members.member_num || 0,
                    purpose: base.purpose || "",
                    create_ts: base.create_ts || 0
                };
            } catch (e) {
                return {
                    club_id: item.club_id,
                    hostnum: item.hostnum,
                    name: "???",
                    error: e.message
                };
            }
        });

        const enriched = await Promise.all(detailPromises);
        console.log(`\x1b[36m[API]\x1b[0m Enriched ${enriched.length} clubs`);

        return res.json({
            server: server,
            keyword: clubName,
            results: enriched,
            count: enriched.length
        });
    } catch (e) {
        console.error(`\x1b[31m[ERR]\x1b[0m Club Search Error: ${e.message}`);
        return res.status(500).json({ error: e.message });
    }
});


/**
 * GET /convert?id=PLAN_ID
 * Face plan data conversion (legacy endpoint)
 */
app.get('/convert', async (req, res) => {
    const plan_id = req.query.id;

    if (!plan_id) {
        return res.json(null);
    }

    const op = "/flk/face_community/get_face_plan_data";
    const payload_id = (plan_id.startsWith("ART")) ? plan_id.substring(3) : plan_id;
    const payload = { "plan_id": payload_id };

    const data = await call_uwsgi(op, payload);

    if (data && data["view_data"]) {
        return res.json({
            "id": plan_id,
            "data": data["view_data"],
            "origin": data
        });
    }
    return res.json(data);
});

// --- START SERVER ---
const PORT = 3003;
app.listen(PORT, () => {
    console.log("\x1b[36m" + "=".repeat(60) + "\x1b[0m");
    console.log("   \x1b[1m\x1b[33mWHERE WINDS MEET API SERVER\x1b[0m");
    console.log(`   \x1b[32mListening on:\x1b[0m http://localhost:${PORT}`);
    console.log("\x1b[36m" + "=".repeat(60) + "\x1b[0m");
    console.log("");
    console.log("   \x1b[1m\x1b[35mEndpoints:\x1b[0m");
    console.log(`   \x1b[36mGET\x1b[0m /id?keyword=KEYWORD           \x1b[90m(bot: auto ID or Name)\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /lookup?id=NUMBER_ID          \x1b[90m(by number_id, all servers)\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /lookup?id=NUMBER_ID&server=SEA \x1b[90m(by number_id, specific)\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /lookup?name=NICKNAME         \x1b[90m(by nickname, all servers)\x1b[0m \x1b[32m✅NEW\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /lookup?name=NICKNAME&server=SEA\x1b[90m(by nickname, specific)\x1b[0m \x1b[32m✅NEW\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /convert?id=PLAN_ID           \x1b[90m(Legacy face plan)\x1b[0m`);
    console.log(`   \x1b[36mGET\x1b[0m /club_search?name=NAME        \x1b[90m(Guild search by name)\x1b[0m \x1b[32m✅NEW\x1b[0m`);
    console.log("");
    console.log("   \x1b[1m\x1b[35mServers:\x1b[0m");
    console.log(`   SEA: \x1b[33m${SERVERS.SEA}\x1b[0m`);
    console.log(`   CN:  \x1b[33m${SERVERS.CN}\x1b[0m`);
    console.log("\x1b[36m" + "=".repeat(60) + "\x1b[0m");
});
