/**
 * Cloudflare Worker — Jekyll classified-advert form handler
 * - Honeypot field check
 * - Cloudflare Turnstile verification
 * - Basic time-trap (rejects submissions too fast to be human)
 * - Sends email via Resend (https://resend.com)
 * - Redirects to thank-you page on success
 *
 * Deployed independently of the site: category is intentionally NOT
 * validated against a fixed list, so new categories can be added on the
 * site without redeploying this worker. All fields are sanitized to plain
 * text before they reach your inbox.
 *
 * Required wrangler.toml vars (set as secrets/vars):
 *   TO_EMAIL          - your destination email address (e.g. you@icloud.com)
 *   FROM_EMAIL        - a verified sender on a domain you've added in Resend
 *                       (e.g. noreply@yourdomain.com)
 *   RESEND_API_KEY    - Resend API key (wrangler secret put RESEND_API_KEY)
 *   TURNSTILE_SECRET  - Cloudflare Turnstile secret key (wrangler secret put TURNSTILE_SECRET)
 *   ALLOWED_ORIGIN    - e.g. https://yourblog.com
 *   THANKYOU_URL      - e.g. https://yourblog.com/thanks/
 *   ERROR_URL         - e.g. https://yourblog.com/error/
 */

export default {
    async fetch(request, env, ctx) {
        if (request.method === "OPTIONS") {
            return handleOptions(request, env);
        }

        if (request.method !== "POST") {
            return new Response("Method not allowed", { status: 405 });
        }

        const origin = request.headers.get("Origin") || "";
        if (env.ALLOWED_ORIGIN && origin && origin !== env.ALLOWED_ORIGIN) {
            return new Response("Forbidden", { status: 403 });
        }

        let form;
        try {
            form = await request.formData();
        } catch (err) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        // --- Spam check 1: honeypot field ---
        // Add a hidden field named "_gotcha" to your Jekyll form.
        // Real users won't fill it; bots often do.
        const honeypot = oneLine(form.get("_gotcha"), 200);
        if (honeypot.length > 0) {
            return Response.redirect(env.THANKYOU_URL, 303); // silently "succeed" to not tip off bots
        }

        // --- Spam check 2: time trap ---
        // Add a hidden field "_ts" set via JS to Date.now() when the form loads.
        // Reject submissions faster than 3 seconds (bots fill instantly).
        const startedAt = parseInt(form.get("_ts") || "0", 10);
        if (startedAt && Date.now() - startedAt < 3000) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        // --- Spam check 3: Cloudflare Turnstile ---
        const turnstileToken = form.get("cf-turnstile-response");
        if (env.TURNSTILE_SECRET) {
            const verified = await verifyTurnstile(
                turnstileToken,
                env.TURNSTILE_SECRET,
                request.headers.get("CF-Connecting-IP"),
            );
            if (!verified) {
                return Response.redirect(env.ERROR_URL, 303);
            }
        }

        // --- Extract fields ---
        // Short fields are forced to a single line (no newlines / control
        // chars) so a tampered form can't inject email headers or garbage.
        // The description keeps line breaks but strips other control chars.
        const advert = {
            name: oneLine(form.get("name"), 200),
            email: oneLine(form.get("email"), 320),
            category: oneLine(form.get("category"), 100),
            title: oneLine(form.get("title"), 200),
            company: oneLine(form.get("company"), 200),
            location: oneLine(form.get("location"), 200),
            salary: oneLine(form.get("salary"), 100),
            jobType: oneLine(form.get("job_type"), 100),
            description: multiLine(form.get("description"), 5000),
            applyUrl: oneLine(form.get("apply_url"), 500),
            expires: oneLine(form.get("expires"), 100),
        };

        // --- Validation ---
        // Required (matches the form's `required` attributes):
        //   name, email, category, title, description
        // Everything else is optional. Category value itself is NOT checked
        // against a list — any non-empty string is accepted.
        if (
            !advert.name ||
            !advert.email ||
            !advert.category ||
            !advert.title ||
            !advert.description ||
            !isValidEmail(advert.email)
        ) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        // --- Send email via Resend ---
        const sent = await sendEmail(env, advert);
        if (!sent) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        return Response.redirect(env.THANKYOU_URL, 303);
    },
};

// Single-line field: trim, strip ALL control chars (incl. newlines/tabs),
// collapse repeated whitespace, then cap length. Used for everything that
// should never contain a line break — including the subject-feeding title.
function oneLine(value, max) {
    return (
        (value || "")
            .toString()
            // eslint-disable-next-line no-control-regex
            .replace(/[\u0000-\u001F\u007F]/g, " ")
            .replace(/\s+/g, " ")
            .trim()
            .slice(0, max)
    );
}

// Multi-line field: preserve newlines, but strip other control chars and
// normalise line endings. Used for the free-text description.
function multiLine(value, max) {
    return (
        (value || "")
            .toString()
            .replace(/\r\n?/g, "\n")
            // strip control chars except newline (\u000A)
            // eslint-disable-next-line no-control-regex
            .replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, " ")
            .trim()
            .slice(0, max)
    );
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function verifyTurnstile(token, secret, ip) {
    if (!token) return false;
    const body = new URLSearchParams();
    body.append("secret", secret);
    body.append("response", token);
    if (ip) body.append("remoteip", ip);

    const resp = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        { method: "POST", body },
    );
    const data = await resp.json();
    return data.success === true;
}

async function sendEmail(env, advert) {
    const {
        name,
        email,
        category,
        title,
        company,
        location,
        salary,
        jobType,
        description,
        applyUrl,
        expires,
    } = advert;

    // Build the plain-text body, including optional fields only when present.
    const lines = [
        `Category:      ${category}`,
        `Title:         ${title}`,
        `Advertiser:    ${name}`,
        `Email:         ${email}`,
    ];

    if (company) lines.push(`Business:      ${company}`);
    if (location) lines.push(`Location:      ${location}`);
    if (salary) lines.push(`Salary/price:  ${salary}`);
    if (jobType) lines.push(`Type:          ${jobType}`);
    if (applyUrl) lines.push(`Apply/contact: ${applyUrl}`);
    if (expires) lines.push(`Closing date:  ${expires}`);

    const text = `${lines.join("\n")}\n\n` + `Details:\n${description}\n`;

    const payload = {
        from: `Adverts <${env.FROM_EMAIL}>`,
        to: [env.TO_EMAIL],
        reply_to: email,
        subject: `New advert: ${title}`,
        text,
    };

    const resp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${env.RESEND_API_KEY}`,
        },
        body: JSON.stringify(payload),
    });

    return resp.status === 200;
}

function handleOptions(request, env) {
    return new Response(null, {
        status: 204,
        headers: {
            "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
    });
}
