/**
 * Cloudflare Worker — Jekyll contact form handler
 * - Honeypot field check
 * - Cloudflare Turnstile verification
 * - Basic time-trap (rejects submissions too fast to be human)
 * - Sends email via Resend (https://resend.com)
 * - Redirects to thank-you page on success
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
        const honeypot = (form.get("_gotcha") || "").toString().trim();
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
        const name = sanitize(form.get("name"));
        const email = sanitize(form.get("email"));
        const message = sanitize(form.get("message"));

        if (!name || !email || !message || !isValidEmail(email)) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        // --- Send email via Resend ---
        const sent = await sendEmail(env, { name, email, message });
        if (!sent) {
            return Response.redirect(env.ERROR_URL, 303);
        }

        return Response.redirect(env.THANKYOU_URL, 303);
    },
};

function sanitize(value) {
    return (value || "").toString().trim().slice(0, 5000);
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

async function sendEmail(env, { name, email, message }) {
    const payload = {
        from: `Mailbox <${env.FROM_EMAIL}>`,
        to: [env.TO_EMAIL],
        reply_to: email,
        subject: `Mailbox: ${name}`,
        text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
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
