// api/truecaller.js

function stripTags(html) {
  // Remove scripts & styles
  let text = html.replace(/<script[\s\S]*?<\/script>/gi, " ");
  text = text.replace(/<style[\s\S]*?<\/style>/gi, " ");
  // Remove all tags
  text = text.replace(/<[^>]+>/g, " ");
  // Collapse whitespace
  return text.replace(/\s+/g, " ").trim();
}

function parseFullProfile(html, phoneInput) {
  const textDump = stripTags(html);
  const lowerText = textDump.toLowerCase();

  const data = {
    phone: phoneInput,
    name: null,
    alt_name: null,
    email: null,
    location: "Unknown",
    carrier: "Unknown",
    image_url: null,
    type: "Person",
    spam_score: null,
    status: "Success",
  };

  // --- 1. vCard extraction ---
  try {
    const vcardMatch = html.match(
      /href="(data:text\/vcard;charset=utf-8,[^"]+)"/i
    );
    if (vcardMatch) {
      const rawVcard = decodeURIComponent(vcardMatch[1]);

      const fnMatch = rawVcard.match(/\nFN:(.+)/);
      if (fnMatch) data.name = fnMatch[1].trim();

      const emailMatch = rawVcard.match(/\nEMAIL:(.+)/);
      if (emailMatch) data.email = emailMatch[1].trim();

      const adrMatch = rawVcard.match(/\nADR.*?:(.*)/);
      if (adrMatch) {
        const loc = adrMatch[1].replace(/;/g, " ").trim();
        if (loc) data.location = loc;
      }
    }
  } catch (e) {
    data.vcard_error = String(e);
  }

  // --- 2. Profile image ---
  const imgRegex = /<img[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let imgMatch;
  while ((imgMatch = imgRegex.exec(html)) !== null) {
    const src = imgMatch[1];
    if (
      (src.includes("myview") ||
        src.includes("googleusercontent") ||
        src.includes("facebook")) &&
      !src.includes("user.svg")
    ) {
      data.image_url = src;
      break;
    }
  }

  // --- 3. Name fallback (class contains "font-bold") ---
  if (!data.name) {
    const nameRegex =
      /<(div|span)[^>]*class=["'][^"']*font-bold[^"']*["'][^>]*>([\s\S]*?)<\/\1>/i;
    const m = html.match(nameRegex);
    if (m) {
      let inner = m[2].replace(/<[^>]+>/g, " ");
      inner = inner.replace(/\s+/g, " ").trim();
      if (inner && !inner.toLowerCase().includes("truecaller")) {
        data.name = inner;
      }
    }
  }

  // --- 4. Alt name (class contains "opacity-75" and has brackets) ---
  const altRegex =
    /<div[^>]*class=["'][^"']*opacity-75[^"']*["'][^>]*>([\s\S]*?)<\/div>/i;
  const altMatch = html.match(altRegex);
  if (altMatch) {
    let inner = altMatch[1].replace(/<[^>]+>/g, " ");
    inner = inner.replace(/\s+/g, " ").trim();
    if (inner.includes("(") && inner.includes(")")) {
      data.alt_name = inner;
    }
  }

  // --- 5. Type / spam ---
  if (lowerText.includes("likely a business")) {
    data.type = "Likely a Business";
  } else if (lowerText.includes("spam")) {
    const count = lowerText.match(/(\d+)\s*spam/);
    if (count) {
      data.spam_score = `Reported ${count[1]} times`;
    } else {
      data.spam_score = "Yes, Reported as Spam";
    }
  }

  // --- 6. Carrier detection ---
  if (data.carrier === "Unknown") {
    const carriers = ["Airtel", "Jio", "Vi", "Vodafone", "Idea", "BSNL", "MTNL"];
    for (const c of carriers) {
      if (lowerText.includes(c.toLowerCase())) {
        data.carrier = c;
        break;
      }
    }
  }

  return data;
}

async function lookupNumber(rawPhone) {
  const cookieHeader = process.env.TC_COOKIE;
  if (!cookieHeader) {
    return {
      status: "Error",
      error:
        "TC_COOKIE env var not set. Set your Truecaller Cookie header in Vercel project settings.",
    };
  }

  const cleaned = (rawPhone || "").replace(/[^\d]/g, "");
  if (!cleaned) {
    return { status: "Error", error: "Phone number is required" };
  }

  let phoneNum = cleaned;
  if (!phoneNum.startsWith("91") && phoneNum.length === 10) {
    phoneNum = "91" + phoneNum;
  }

  const targetUrl = `https://www.truecaller.com/search/in/${phoneNum}`;

  let resp;
  try {
    resp = await fetch(targetUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        Referer: "https://www.truecaller.com/",
        Cookie: cookieHeader,
      },
    });
  } catch (e) {
    return {
      status: "Error",
      error: "Request to Truecaller failed",
      details: String(e),
    };
  }

  const status = resp.status;
  const html = await resp.text();

  if (status === 200) {
    const lowerHtml = html.toLowerCase();
    if (lowerHtml.includes("sign in") && lowerHtml.includes("unlock")) {
      return {
        status: "Error",
        error: "Login expired or IP blocked by Truecaller",
      };
    }
    return parseFullProfile(html, phoneNum);
  }

  if (status === 404) {
    return {
      status: "NotFound",
      error: "Number not found in Truecaller database",
      phone: phoneNum,
    };
  }

  if (status === 403) {
    return {
      status: "Forbidden",
      error: "403 Blocked (WAF or IP blocked)",
      phone: phoneNum,
    };
  }

  return {
    status: "Error",
    error: `Unexpected HTTP status code: ${status}`,
    phone: phoneNum,
  };
}

// Vercel Node.js function handler
export default async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const phone =
    url.searchParams.get("phone") || url.searchParams.get("mobile");

  if (!phone) {
    res
      .status(400)
      .json({
        status: "Error",
        error:
          "Query param 'phone' or 'mobile' is required, e.g. /api/truecaller?phone=9199XXXXXXXX",
      });
    return;
  }

  const result = await lookupNumber(phone);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");

  if (result.status === "Success") res.status(200).json(result);
  else if (result.status === "NotFound") res.status(404).json(result);
  else if (result.status === "Forbidden") res.status(403).json(result);
  else res.status(500).json(result);
}
