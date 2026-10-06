import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const TELEGRAM_BOT_TOKEN = Deno.env.get("TELEGRAM_BOT_TOKEN")!;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

const CYCLE_SECONDS = 4 * 60 * 60;
const BASE_RATE = 1.0;
const BOOST_BONUS = 0.5;
const REFERRAL_BONUS = 0.1;
const MAX_BOOSTERS = 5;
const MAX_LUCKY_BOXES = 5;
const MIN_TRANSFER_AMOUNT = 100.0;
const TASK_REWARD = 5.0;
const ADSGRAM_BLOCK_ID = "49196";
const MAX_INIT_DATA_AGE_SECONDS = 24 * 60 * 60;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "content-type, x-telegram-init-data, authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function nowIso() {
  return new Date().toISOString();
}

function num(value: unknown, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function money(value: number) {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function cleanUsername(value: unknown) {
  return String(value ?? "")
    .replace(/^@/, "")
    .trim()
    .toLowerCase();
}

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function hmacSha256(key: Uint8Array, data: string) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(data),
  );

  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function validateTelegramInitData(initData: string) {
  if (!initData || !TELEGRAM_BOT_TOKEN) {
    throw new Error("Telegram authentication is unavailable.");
  }

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");

  if (!hash) {
    throw new Error("Invalid Telegram authentication data.");
  }

  const authDate = Number(params.get("auth_date") || 0);

  const age = Math.floor(Date.now() / 1000) - authDate;

  if (
    !authDate ||
    age < -300 ||
    age > MAX_INIT_DATA_AGE_SECONDS
  ) {
    throw new Error("Telegram authentication data has expired.");
  }

  const pairs: string[] = [];

  for (const [key, value] of params.entries()) {
    if (key !== "hash") {
      pairs.push(`${key}=${value}`);
    }
  }

  pairs.sort();

  const dataCheckString = pairs.join("\n");

  const secretKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("WebAppData"),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const secretSignature = await crypto.subtle.sign(
    "HMAC",
    secretKey,
    new TextEncoder().encode(TELEGRAM_BOT_TOKEN),
  );

  const expectedHash = await hmacSha256(
    new Uint8Array(secretSignature),
    dataCheckString,
  );

  if (!timingSafeEqual(expectedHash, hash.toLowerCase())) {
    throw new Error(
      "Telegram authentication verification failed.",
    );
  }

  const rawUser = params.get("user");

  if (!rawUser) {
    throw new Error(
      "Telegram user information is missing.",
    );
  }

  const user = JSON.parse(rawUser);

  if (!user?.id) {
    throw new Error("Telegram user ID is missing.");
  }

  return {
    id: String(user.id),
    username: user.username
      ? String(user.username)
      : null,
    firstName: user.first_name
      ? String(user.first_name)
      : null,
    lastName: user.last_name
      ? String(user.last_name)
      : null,
    languageCode: user.language_code
      ? String(user.language_code)
      : null,
    startParam: params.get("start_param")
      ? String(params.get("start_param"))
      : null,
  };
}

async function authenticate(req: Request) {
  const initData =
    req.headers.get("x-telegram-init-data") ||
    (req.headers.get("authorization") || "")
      .replace(/^Bearer\s+/i, "");

  return validateTelegramInitData(initData);
}

async function ensureUser(
  tg: Awaited<
    ReturnType<typeof validateTelegramInitData>
  >,
) {
  const id = Number(tg.id);

  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new Error("Invalid Telegram user ID.");
  }

  const {
    data: existing,
    error: readError,
  } = await supabase
    .from("users")
    .select("id,username,balance,created_at")
    .eq("id", id)
    .maybeSingle();

  if (readError) {
    throw readError;
  }

  if (existing) {
    if (existing.username !== (tg.username || null)) {
      const { error } = await supabase
        .from("users")
        .update({
          username: tg.username || null,
        })
        .eq("id", id);

      if (error) {
        throw error;
      }

      existing.username = tg.username || null;
    }

    return existing;
  }

  const {
    data: created,
    error: createError,
  } = await supabase
    .from("users")
    .insert({
      id,
      username: tg.username || null,
      balance: 0,
    })
    .select("id,username,balance,created_at")
    .single();

  if (createError) {
    throw createError;
  }

  return created;
}

async function getUser(
  tg: Awaited<
    ReturnType<typeof validateTelegramInitData>
  >,
) {
  return ensureUser(tg);
}

async function getLatestSession(userId: number) {
  const {
    data,
    error,
  } = await supabase
    .from("mining_sessions")
    .select("*")
    .eq("user_id", userId)
    .order("start_time", {
      ascending: false,
    })
    .limit(1)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

async function refreshMiningSession(userId: number) {
  const session = await getLatestSession(userId);

  if (!session) {
    return null;
  }

  if (
    session.status === "active" &&
    new Date(session.end_time).getTime() <= Date.now()
  ) {
    const {
      data,
      error,
    } = await supabase
      .from("mining_sessions")
      .update({
        status: "completed",
      })
      .eq("id", session.id)
      .eq("status", "active")
      .select("*")
      .maybeSingle();

    if (error) {
      throw error;
    }

    return data || session;
  }

  return session;
}

async function getReferralBonus(userId: number) {
  const {
    data: referrals,
    error,
  } = await supabase
    .from("referrals")
    .select("referred_id")
    .eq("referrer_id", userId);

  if (error) {
    throw error;
  }

  if (!referrals?.length) {
    return {
      active: 0,
      bonus: 0,
    };
  }

  const referredIds = referrals
    .map((r: any) => Number(r.referred_id))
    .filter((id: number) => Number.isSafeInteger(id) && id > 0);

  if (!referredIds.length) {
    return {
      active: 0,
      bonus: 0,
    };
  }

  // A referral is ACTIVE only while the invitee's CURRENT mining cycle
  // is actually running. Historical claimed/completed sessions must not
  // keep the inviter's bonus active.
  const now = Date.now();

  const {
    data: sessions,
    error: sessionError,
  } = await supabase
    .from("mining_sessions")
    .select("user_id,status,start_time,end_time")
    .in("user_id", referredIds)
    .eq("status", "active")
    .gt("end_time", new Date(now).toISOString());

  if (sessionError) {
    throw sessionError;
  }

  const activeIds = new Set(
    (sessions || [])
      .filter((s: any) => {
        const end = new Date(s.end_time).getTime();
        const start = new Date(s.start_time).getTime();
        return Number.isFinite(start) && Number.isFinite(end) && start <= now && end > now;
      })
      .map((s: any) => Number(s.user_id)),
  );

  const active = referredIds.filter(
    (id) => activeIds.has(id),
  ).length;

  return {
    active,
    bonus: money(active * REFERRAL_BONUS),
  };
}

async function getBoosterCount(userId: number) {
  const session = await getLatestSession(userId);

  if (!session || session.status !== "active") {
    return 0;
  }

  const cycleStart = new Date(
    session.start_time,
  ).getTime();

  const {
    count,
    error,
  } = await supabase
    .from("fidexa_boosters")
    .select("id", {
      count: "exact",
      head: true,
    })
    .eq("user_id", userId)
    .gte(
      "used_at",
      new Date(cycleStart).toISOString(),
    );

  if (error) {
    throw error;
  }

  return count || 0;
}

async function getLuckyBoxCount(userId: number) {
  const session = await getLatestSession(userId);

  if (!session || session.status !== "active") {
    return 0;
  }

  const cycleStart = new Date(
    session.start_time,
  ).getTime();

  const {
    count,
    error,
  } = await supabase
    .from("fidexa_lucky_boxes")
    .select("id", {
      count: "exact",
      head: true,
    })
    .eq("user_id", userId)
    .gte(
      "opened_at",
      new Date(cycleStart).toISOString(),
    );

  if (error) {
    throw error;
  }

  return count || 0;
}

async function getTotalMined(userId: number) {
  const {
    data,
    error,
  } = await supabase
    .from("mining_sessions")
    .select("total_reward")
    .eq("user_id", userId)
    .eq("status", "claimed");

  if (error) {
    throw error;
  }

  return money(
    (data || []).reduce(
      (sum: number, row: any) =>
        sum + num(row.total_reward),
      0,
    ),
  );
}

async function userPayload(
  user: any,
  session: any,
  referral: any,
) {
  const boosterCount =
    await getBoosterCount(Number(user.id));

  const luckyCount =
    await getLuckyBoxCount(Number(user.id));

  const totalMined =
    await getTotalMined(Number(user.id));

  const claimedTasks =
    await getClaimedTasks(Number(user.id));

  let miningState = "IDLE";

  if (session?.status === "active") {
    if (
      new Date(session.end_time).getTime() <=
      Date.now()
    ) {
      miningState = "READY_TO_CLAIM";
    } else {
      miningState = "MINING";
    }
  } else if (session?.status === "completed") {
    miningState = "READY_TO_CLAIM";
  }

  return {
    userId: String(user.id),
    username: user.username || null,

    totalBalance: num(user.balance),
    totalMined,

    miningCycleDuration: CYCLE_SECONDS,

    baseMiningRate: BASE_RATE,

    boosterBonusRate: money(
      boosterCount * BOOST_BONUS,
    ),

    referralBonusRate: referral.bonus,

    boosterChancesLeft: Math.max(
      0,
      MAX_BOOSTERS - boosterCount,
    ),

    luckyBoxChances: Math.max(
      0,
      MAX_LUCKY_BOXES - luckyCount,
    ),

    miningState,

    miningStartedAt: session
      ? new Date(
          session.start_time,
        ).getTime()
      : 0,

    miningEndAt: session
      ? new Date(
          session.end_time,
        ).getTime()
      : 0,

    sessionRate: session
      ? num(session.mining_rate, BASE_RATE)
      : 0,

    sessionAccumulated: session
      ? num(session.total_reward)
      : 0,

    activeReferrals: referral.active,

    claimedTasks,
  };
}

async function handleHealth() {
  return json({
    success: true,
    status: "online",
    service: "fidexa-api",
    miningCycle: "4 hours",
  });
}

async function handleMe(req: Request) {
  const tg = await authenticate(req);

  const user = await ensureUser(tg);

  const url = new URL(req.url);
  const refFromQuery = String(url.searchParams.get("ref") || "").trim();
  const refFromTelegram = String(tg.startParam || "").trim();
  await registerReferralIfNeeded(
    Number(tg.id),
    refFromQuery || refFromTelegram,
  );

  const session =
    await refreshMiningSession(
      Number(tg.id),
    );

  const referral =
    await getReferralBonus(
      Number(tg.id),
    );

  return json({
    success: true,
    user: await userPayload(
      user,
      session,
      referral,
    ),
  });
}

async function handleMiningStart(req: Request) {
  const tg = await authenticate(req);

  await getUser(tg);

  const userId = Number(tg.id);

  const session =
    await refreshMiningSession(userId);

  if (session?.status === "active") {
    return json(
      {
        success: false,
        error:
          "Mining is already in progress.",
      },
      409,
    );
  }

  if (session?.status === "completed") {
    return json(
      {
        success: false,
        error:
          "Mining session is ready to claim.",
      },
      409,
    );
  }

  const referral =
    await getReferralBonus(userId);

  const miningRate = money(
    BASE_RATE + referral.bonus,
  );

  const totalReward = money(
    miningRate * 4,
  );

  const start = new Date();

  const end = new Date(
    start.getTime() +
      CYCLE_SECONDS * 1000,
  );

  const {
    data: created,
    error,
  } = await supabase
    .from("mining_sessions")
    .insert({
      user_id: userId,
      start_time: start.toISOString(),
      end_time: end.toISOString(),
      mining_rate: miningRate,
      total_reward: totalReward,
      status: "active",
    })
    .select("*")
    .single();

  if (error) {
    throw error;
  }

  return json({
    success: true,

    message:
      "Mining cycle started!",

    mining: {
      state: "MINING",
      miningState: "MINING",

      miningStartedAt:
        start.getTime(),

      miningEndAt:
        end.getTime(),

      cycleDuration:
        CYCLE_SECONDS,

      sessionRate:
        miningRate,

      totalReward,

      sessionId:
        created.id,
    },
  });
}

async function handleMiningClaim(req: Request) {
  const tg = await authenticate(req);

  const userId = Number(tg.id);

  await getUser(tg);

  const body =
    await req.json().catch(() => ({}));

  if (body.adCompleted !== true) {
    return json(
      {
        success: false,
        error:
          "A successful Adsgram reward is required before the mining reward can be credited.",
      },
      400,
    );
  }

  const session =
    await refreshMiningSession(userId);

  if (!session) {
    return json(
      {
        success: false,
        error:
          "No mining session found.",
      },
      404,
    );
  }

  if (
    new Date(
      session.end_time,
    ).getTime() > Date.now()
  ) {
    return json(
      {
        success: false,
        error:
          "Mining is still active.",

        remainingMs:
          new Date(
            session.end_time,
          ).getTime() -
          Date.now(),
      },
      409,
    );
  }

  if (session.status !== "completed") {
    return json(
      {
        success: false,
        error:
          "Mining reward has already been claimed.",
      },
      409,
    );
  }

  const reward =
    num(session.total_reward);

  const {
    data: currentUser,
    error: userError,
  } = await supabase
    .from("users")
    .select("id,balance")
    .eq("id", userId)
    .single();

  if (userError) {
    throw userError;
  }

  const newBalance = money(
    num(currentUser.balance) +
      reward,
  );

  const {
    error: balanceError,
  } = await supabase
    .from("users")
    .update({
      balance: newBalance,
    })
    .eq("id", userId)
    .eq(
      "balance",
      currentUser.balance,
    );

  if (balanceError) {
    throw balanceError;
  }

  const {
    error: sessionError,
  } = await supabase
    .from("mining_sessions")
    .update({
      claimed_at: nowIso(),
      status: "claimed",
    })
    .eq("id", session.id)
    .eq("status", "completed");

  if (sessionError) {
    throw sessionError;
  }

  await supabase
    .from("fidexa_claims")
    .insert({
      user_id: userId,
      mining_session_id:
        session.id,
      claim_type: "MINING",
      amount: reward,
    });

  await supabase
    .from("fidexa_ad_events")
    .insert({
      user_id: userId,
      ad_type:
        "MINING_CLAIM",
      block_id:
        ADSGRAM_BLOCK_ID,
      status:
        "completed",
      reward,
    });

  return json({
    success: true,

    reward,

    totalBalance:
      newBalance,

    miningState:
      "IDLE",

    sessionAccumulated:
      0,
  });
}

async function handleBoost(req: Request) {
  const tg = await authenticate(req);

  const userId = Number(tg.id);

  await getUser(tg);

  const body =
    await req.json().catch(() => ({}));

  if (body.adCompleted !== true) {
    return json(
      {
        success: false,
        error:
          "A completed Adsgram reward is required.",
      },
      400,
    );
  }

  const session =
    await getLatestSession(userId);

  if (
    !session ||
    session.status !== "active"
  ) {
    return json(
      {
        success: false,
        error:
          "Start mining before using Mining Boost.",
      },
      409,
    );
  }

  const used =
    await getBoosterCount(userId);

  if (used >= MAX_BOOSTERS) {
    return json(
      {
        success: false,
        error:
          "No booster chances left.",
      },
      409,
    );
  }

  const {
    error,
  } = await supabase
    .from("fidexa_boosters")
    .insert({
      user_id: userId,
      bonus_rate:
        BOOST_BONUS,
    });

  if (error) {
    throw error;
  }

  const nextUsed =
    used + 1;

  const nextBonus =
    money(
      nextUsed *
        BOOST_BONUS,
    );

  await supabase
    .from("fidexa_ad_events")
    .insert({
      user_id: userId,
      ad_type:
        "MINING_BOOST",
      block_id:
        ADSGRAM_BLOCK_ID,
      status:
        "completed",
      reward:
        BOOST_BONUS,
    });

  return json({
    success: true,

    boosterBonusRate:
      nextBonus,

    boosterChancesLeft:
      MAX_BOOSTERS -
      nextUsed,
  });
}

async function handleLuckyBox(req: Request) {
  const tg = await authenticate(req);

  const userId = Number(tg.id);

  const user =
    await getUser(tg);

  const body =
    await req.json().catch(() => ({}));

  if (body.adCompleted !== true) {
    return json(
      {
        success: false,
        error:
          "A completed Adsgram reward is required.",
      },
      400,
    );
  }

  const session =
    await getLatestSession(userId);

  if (
    !session ||
    session.status !== "active"
  ) {
    return json(
      {
        success: false,
        error:
          "Start mining before using Lucky Box.",
      },
      409,
    );
  }

  const used =
    await getLuckyBoxCount(
      userId,
    );

  if (
    used >=
    MAX_LUCKY_BOXES
  ) {
    return json(
      {
        success: false,
        error:
          "No Lucky Box chances left.",
      },
      409,
    );
  }

  const rewards = [
    1,
    2,
    3,
    5,
    10,
  ];

  const reward =
    rewards[
      Math.floor(
        Math.random() *
          rewards.length,
      )
    ];

  const newBalance =
    money(
      num(user.balance) +
        reward,
    );

  const {
    error: boxError,
  } = await supabase
    .from("fidexa_lucky_boxes")
    .insert({
      user_id: userId,
      reward,
    });

  if (boxError) {
    throw boxError;
  }

  const {
    error: balanceError,
  } = await supabase
    .from("users")
    .update({
      balance:
        newBalance,
    })
    .eq("id", userId)
    .eq(
      "balance",
      user.balance,
    );

  if (balanceError) {
    throw balanceError;
  }

  await supabase
    .from("fidexa_ad_events")
    .insert({
      user_id: userId,
      ad_type:
        "LUCKY_BOX",
      block_id:
        ADSGRAM_BLOCK_ID,
      status:
        "completed",
      reward,
    });

  return json({
    success: true,

    reward,

    totalBalance:
      newBalance,

    luckyBoxChances:
      MAX_LUCKY_BOXES -
      used -
      1,
  });
}

async function handleReferrals(req: Request) {
  const tg = await authenticate(req);

  const userId = Number(tg.id);

  await getUser(tg);

  const {
    data,
    error,
  } = await supabase
    .from("referrals")
    .select("id,referrer_id,referred_id,created_at")
    .eq("referrer_id", userId)
    .order("created_at", { ascending: false });

  if (error) {
    throw error;
  }

  const referrals = data || [];

  if (!referrals.length) {
    return json({
      success: true,
      referrals: [],
      total: 0,
      active: 0,
      inactive: 0,
      referralBonusRate: 0,
    });
  }

  const referredIds = referrals
    .map((r: any) => Number(r.referred_id))
    .filter((id: number) => Number.isSafeInteger(id) && id > 0);

  const now = Date.now();

  // Only the invitee's CURRENT active mining cycle counts.
  // Old claimed/completed sessions never count as active.
  let activeSessions: any[] = [];

  if (referredIds.length) {
    const {
      data: sessions,
      error: sessionError,
    } = await supabase
      .from("mining_sessions")
      .select("user_id,status,start_time,end_time")
      .in("user_id", referredIds)
      .eq("status", "active")
      .gt("end_time", new Date(now).toISOString());

    if (sessionError) {
      throw sessionError;
    }

    activeSessions = (sessions || []).filter((s: any) => {
      const start = new Date(s.start_time).getTime();
      const end = new Date(s.end_time).getTime();
      return Number.isFinite(start) && Number.isFinite(end) && start <= now && end > now;
    });
  }

  const activeIds = new Set(
    activeSessions.map((s: any) => Number(s.user_id)),
  );

  // Include the invitee's username so the Friends page has useful
  // member information instead of only a numeric Telegram ID.
  const {
    data: users,
    error: usersError,
  } = await supabase
    .from("users")
    .select("id,username")
    .in("id", referredIds);

  if (usersError) {
    throw usersError;
  }

  const usernameById = new Map(
    (users || []).map((u: any) => [Number(u.id), u.username || null]),
  );

  const result = referrals.map((r: any) => {
    const referredId = Number(r.referred_id);
    const isActive = activeIds.has(referredId);

    return {
      id: String(r.id),
      referredId: String(referredId),
      username: usernameById.get(referredId) || null,
      status: isActive ? "active" : "inactive",
      active: isActive,
      createdAt: r.created_at,
    };
  });

  const active = result.filter((r: any) => r.active).length;

  return json({
    success: true,
    referrals: result,
    total: result.length,
    active,
    inactive: result.length - active,
    referralBonusRate: money(active * REFERRAL_BONUS),
  });
}

async function registerReferralIfNeeded(
  referredUserId: number,
  rawRef: unknown,
) {
  const ref = String(rawRef ?? "").replace(/^ref_/i, "").trim();
  if (!ref) return { registered: false, reason: "no_ref" };

  const referrerId = Number(ref);
  if (!Number.isSafeInteger(referrerId) || referrerId <= 0 || referrerId === referredUserId) {
    return { registered: false, reason: "invalid_ref" };
  }

  const { data: referrer, error: referrerError } = await supabase
    .from("users")
    .select("id")
    .eq("id", referrerId)
    .maybeSingle();
  if (referrerError) throw referrerError;
  if (!referrer) return { registered: false, reason: "referrer_not_found" };

  const { data: existing, error: existingError } = await supabase
    .from("referrals")
    .select("id")
    .eq("referred_id", referredUserId)
    .maybeSingle();
  if (existingError) throw existingError;
  if (existing) return { registered: false, alreadyRegistered: true };

  const { error: insertError } = await supabase.from("referrals").insert({
    referrer_id: referrerId,
    referred_id: referredUserId,
  });

  if (insertError) {
    // A duplicate referral is safe to treat as already registered.
    if ((insertError as any).code === "23505") {
      return {
        registered: false,
        alreadyRegistered: true,
        referrerId: String(referrerId),
      };
    }

    console.error("Referral insert failed", {
      referrerId,
      referredUserId,
      code: (insertError as any).code,
      message: (insertError as any).message,
      details: (insertError as any).details,
      hint: (insertError as any).hint,
    });

    throw insertError;
  }

  return {
    registered: true,
    alreadyRegistered: false,
    referrerId: String(referrerId),
  };
}

async function handleReferralRegister(
  req: Request,
) {
  const tg = await authenticate(req);
  await getUser(tg);
  const body = await req.json().catch(() => ({}));
  const result = await registerReferralIfNeeded(
    Number(tg.id),
    body.referrerId || body.ref || body.start_param,
  );
  return json({ success: true, ...result });
}

async function verifyTelegramMembership(userId: number) {
  const channel = "@fidexa_Network";

  if (!TELEGRAM_BOT_TOKEN) {
    throw new Error("Telegram bot token is not configured.");
  }

  const url = new URL(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getChatMember`,
  );

  url.searchParams.set("chat_id", channel);
  url.searchParams.set("user_id", String(userId));

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      "Accept": "application/json",
    },
  });

  const result = await response.json().catch(() => null);

  if (!response.ok || !result?.ok) {
    console.error("Telegram getChatMember error", result);
    throw new Error(
      "Telegram membership verification is temporarily unavailable.",
    );
  }

  const member = result.result;
  const status = String(member?.status || "").toLowerCase();

  const isMember =
    status === "creator" ||
    status === "administrator" ||
    status === "member" ||
    (status === "restricted" && member?.is_member === true);

  return {
    isMember,
    status,
    channel,
  };
}

async function getClaimedTasks(userId: number) {
  const { data, error } = await supabase
    .from("fidexa_claims")
    .select("claim_type")
    .eq("user_id", userId)
    .in("claim_type", [
      "TASK_TELEGRAM",
      "TASK_X",
      "TASK_YOUTUBE",
    ]);

  if (error) {
    throw error;
  }

  const claimedTasks = {
    telegram: false,
    x: false,
    youtube: false,
  };

  for (const row of data || []) {
    if (row.claim_type === "TASK_TELEGRAM") claimedTasks.telegram = true;
    if (row.claim_type === "TASK_X") claimedTasks.x = true;
    if (row.claim_type === "TASK_YOUTUBE") claimedTasks.youtube = true;
  }

  return claimedTasks;
}

async function handleTaskClaim(
  req: Request,
) {
  const tg = await authenticate(req);

  const userId = Number(tg.id);
  const user = await getUser(tg);

  const body = await req.json().catch(() => ({}));
  const task = String(body.task || "").toLowerCase();

  if (!["telegram", "x", "youtube"].includes(task)) {
    return json(
      {
        success: false,
        error: "Unknown task.",
      },
      400,
    );
  }

  const claimType = `TASK_${task.toUpperCase()}`;

  const { data: existing, error: existingError } = await supabase
    .from("fidexa_claims")
    .select("id")
    .eq("user_id", userId)
    .eq("claim_type", claimType)
    .maybeSingle();

  if (existingError) {
    throw existingError;
  }

  if (existing) {
    return json(
      {
        success: false,
        claimed: true,
        error: "Task already claimed.",
      },
      409,
    );
  }

  // Telegram is the task that requires genuine membership verification.
  // X and YouTube keep their existing claim behavior.
  if (task === "telegram") {
    const membership = await verifyTelegramMembership(userId);

    if (!membership.isMember) {
      return json(
        {
          success: false,
          claimed: false,
          verified: false,
          task,
          error: `Please join ${membership.channel} first, then tap VERIFY JOIN.`,
        },
        403,
      );
    }
  }

  const newBalance = money(
    num(user.balance) + TASK_REWARD,
  );

  const { error: claimError } = await supabase
    .from("fidexa_claims")
    .insert({
      user_id: userId,
      claim_type: claimType,
      amount: TASK_REWARD,
    });

  if (claimError) {
    // Protect against a second claim if the database has a unique constraint.
    if ((claimError as any).code === "23505") {
      return json(
        {
          success: false,
          claimed: true,
          error: "Task already claimed.",
        },
        409,
      );
    }
    throw claimError;
  }

  const { error: balanceError } = await supabase
    .from("users")
    .update({
      balance: newBalance,
    })
    .eq("id", userId)
    .eq("balance", user.balance);

  if (balanceError) {
    // Do not leave a claim behind if the balance update failed.
    await supabase
      .from("fidexa_claims")
      .delete()
      .eq("id", (await supabase
        .from("fidexa_claims")
        .select("id")
        .eq("user_id", userId)
        .eq("claim_type", claimType)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle()).data?.id || "");
    throw balanceError;
  }

  return json({
    success: true,
    claimed: true,
    verified: task === "telegram" ? true : undefined,
    reward: TASK_REWARD,
    totalBalance: newBalance,
    task,
  });
}

async function handleTransactions(
  req: Request,
) {
  const tg =
    await authenticate(req);

  const userId =
    Number(tg.id);

  await getUser(tg);

  const {
    data: transfers,
    error,
  } = await supabase
    .from("wallet_transactions")
    .select(
      "id,sender_id,recipient_id,amount,created_at",
    )
    .or(
      `sender_id.eq.${userId},recipient_id.eq.${userId}`,
    )
    .order(
      "created_at",
      {
        ascending:
          false,
      },
    )
    .limit(100);

  if (error) {
    throw error;
  }

  const {
    data: claims,
    error:
      claimError,
  } = await supabase
    .from("fidexa_claims")
    .select(
      "id,claim_type,amount,created_at",
    )
    .eq(
      "user_id",
      userId,
    )
    .order(
      "created_at",
      {
        ascending:
          false,
      },
    )
    .limit(100);

  if (claimError) {
    throw claimError;
  }

  const transactions = [
    ...(transfers || []).map(
      (t: any) => ({
        id: t.id,

        type:
          Number(
            t.sender_id,
          ) === userId
            ? "SEND"
            : "RECEIVE",

        amount:
          Number(
            t.amount,
          ),

        senderId:
          t.sender_id,

        recipientId:
          t.recipient_id,

        createdAt:
          t.created_at,
      }),
    ),

    ...(claims || []).map(
      (c: any) => ({
        id: c.id,

        type:
          c.claim_type,

        amount:
          Number(
            c.amount,
          ),

        createdAt:
          c.created_at,
      }),
    ),
  ]
    .sort(
      (a, b) =>
        new Date(
          b.createdAt,
        ).getTime() -
        new Date(
          a.createdAt,
        ).getTime(),
    )
    .slice(0, 100);

  return json({
    success: true,
    transactions,
  });
}

async function handleWalletSend(
  req: Request,
) {
  const tg =
    await authenticate(req);

  const senderId =
    Number(tg.id);

  const sender =
    await getUser(tg);

  const body =
    await req.json().catch(
      () => ({}),
    );

  const recipientInput =
    String(
      body.recipient ||
        body.address ||
        body.username ||
        "",
    ).trim();

  const amount =
    num(body.amount);

  if (
    !recipientInput ||
    amount <= 0
  ) {
    return json(
      {
        success: false,
        error:
          "Invalid recipient or amount.",
      },
      400,
    );
  }

  if (amount < MIN_TRANSFER_AMOUNT) {
    return json(
      {
        success: false,
        error: `Minimum transfer amount is ${MIN_TRANSFER_AMOUNT} FDX.`,
      },
      400,
    );
  }

  let recipientId =
    0;

  const directId =
    recipientInput.replace(
      /^fdx_node_/i,
      "",
    );

  if (
    /^\d+$/.test(
      directId,
    )
  ) {
    recipientId =
      Number(
        directId,
      );
  } else {
    const username =
      cleanUsername(
        recipientInput,
      );

    const {
      data: recipient,
      error,
    } = await supabase
      .from("users")
      .select("id")
      .ilike(
        "username",
        username,
      )
      .maybeSingle();

    if (error) {
      throw error;
    }

    recipientId =
      Number(
        recipient?.id ||
          0,
      );
  }

  if (
    !Number.isSafeInteger(
      recipientId,
    ) ||
    recipientId <= 0
  ) {
    return json(
      {
        success: false,
        error:
          "Recipient not found.",
      },
      404,
    );
  }

  if (
    recipientId ===
    senderId
  ) {
    return json(
      {
        success: false,
        error:
          "You cannot send to yourself.",
      },
      400,
    );
  }

  if (
    num(sender.balance) <
    amount
  ) {
    return json(
      {
        success: false,
        error:
          "Insufficient Total Balance for transfer.",
      },
      409,
    );
  }

  const {
    data: recipient,
    error:
      recipientError,
  } = await supabase
    .from("users")
    .select(
      "id,balance",
    )
    .eq(
      "id",
      recipientId,
    )
    .maybeSingle();

  if (recipientError) {
    throw recipientError;
  }

  if (!recipient) {
    return json(
      {
        success: false,
        error:
          "Recipient not found.",
      },
      404,
    );
  }

  const senderBalance =
    money(
      num(sender.balance) -
        amount,
    );

  const recipientBalance =
    money(
      num(
        recipient.balance,
      ) +
        amount,
    );

  const {
    error:
      senderUpdate,
  } = await supabase
    .from("users")
    .update({
      balance:
        senderBalance,
    })
    .eq(
      "id",
      senderId,
    )
    .eq(
      "balance",
      sender.balance,
    );

  if (senderUpdate) {
    throw senderUpdate;
  }

  const {
    error:
      recipientUpdate,
  } = await supabase
    .from("users")
    .update({
      balance:
        recipientBalance,
    })
    .eq(
      "id",
      recipientId,
    )
    .eq(
      "balance",
      recipient.balance,
    );

  if (recipientUpdate) {
    await supabase
      .from("users")
      .update({
        balance:
          sender.balance,
      })
      .eq(
        "id",
        senderId,
      );

    throw recipientUpdate;
  }

  const {
    error:
      txError,
  } = await supabase
    .from("wallet_transactions")
    .insert({
      sender_id:
        senderId,

      recipient_id:
        recipientId,

      amount,
    });

  if (txError) {
    await supabase
      .from("users")
      .update({
        balance:
          sender.balance,
      })
      .eq(
        "id",
        senderId,
      );

    await supabase
      .from("users")
      .update({
        balance:
          recipient.balance,
      })
      .eq(
        "id",
        recipientId,
      );

    throw txError;
  }

  return json({
    success: true,

    amount,

    recipientId:
      String(
        recipientId,
      ),

    totalBalance:
      senderBalance,

    transactionTime:
      nowIso(),
  });
}

async function route(req: Request) {
  if (
    req.method ===
    "OPTIONS"
  ) {
    return new Response(
      null,
      {
        status: 204,
        headers:
          corsHeaders,
      },
    );
  }

  const url =
    new URL(req.url);

  /*
   * Supabase can expose the Edge Function path
   * in different forms. Normalize both possible
   * prefixes before matching the API routes.
   */
  const pathname =
    url.pathname
      .replace(
        /^\/functions\/v1\/fidexa-api/,
        "",
      )
      .replace(
        /^\/fidexa-api/,
        "",
      ) || "/";

  if (
    pathname === "/" ||
    pathname ===
      "/api/health"
  ) {
    return handleHealth();
  }

  if (
    pathname ===
      "/api/me" &&
    req.method ===
      "GET"
  ) {
    return handleMe(req);
  }

  if (
    pathname ===
      "/api/mining/start" &&
    req.method ===
      "POST"
  ) {
    return handleMiningStart(
      req,
    );
  }

  if (
    pathname ===
      "/api/mining/claim" &&
    req.method ===
      "POST"
  ) {
    return handleMiningClaim(
      req,
    );
  }

  if (
    pathname ===
      "/api/mining/boost" &&
    req.method ===
      "POST"
  ) {
    return handleBoost(
      req,
    );
  }

  if (
    pathname ===
      "/api/lucky-box" &&
    req.method ===
      "POST"
  ) {
    return handleLuckyBox(
      req,
    );
  }

  if (
    pathname ===
      "/api/referrals" &&
    req.method ===
      "GET"
  ) {
    return handleReferrals(
      req,
    );
  }

  if (
    pathname ===
      "/api/referrals/register" &&
    req.method ===
      "POST"
  ) {
    return handleReferralRegister(
      req,
    );
  }

  if (
    pathname ===
      "/api/tasks/claim" &&
    req.method ===
      "POST"
  ) {
    return handleTaskClaim(
      req,
    );
  }

  if (
    pathname ===
      "/api/wallet/transactions" &&
    req.method ===
      "GET"
  ) {
    return handleTransactions(
      req,
    );
  }

  if (
    pathname ===
      "/api/wallet/send" &&
    req.method ===
      "POST"
  ) {
    return handleWalletSend(
      req,
    );
  }

  return json(
    {
      success: false,
      error:
        "Endpoint not found",
    },
    404,
  );
}

Deno.serve(
  async (req) => {
    try {
      return await route(
        req,
      );
    } catch (error) {
      console.error(
        "FIDEXA API error",
        error,
      );

      return json(
        {
          success: false,
          error:
            error instanceof Error
              ? error.message
              : "Internal server error",
        },
        500,
      );
    }
  },
);