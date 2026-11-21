// Fonction "wave-webhook" : Wave nous prévient ici quand un paiement est réussi ou refusé.
// Seul ce message signé par Wave peut confirmer une réservation.
// Secrets à créer dans Supabase (Edge Functions > Secrets) :
//   WAVE_WEBHOOK_SECRET : le "Signing Secret" affiché une seule fois par Wave
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const reply = (status: number, body: unknown = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function secretKey(): string {
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;
  try {
    const keys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}");
    const first = Object.values(keys)[0];
    if (typeof first === "string") return first;
  } catch (_) { /* ignoré */ }
  return Deno.env.get("SUPABASE_SECRET_KEY") ?? "";
}

async function hmacHex(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sameText(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return reply(405);
  const secret = Deno.env.get("WAVE_WEBHOOK_SECRET");
  if (!secret) return reply(503, { message: "Secret Wave manquant." });

  const raw = await req.text(); // le corps EXACT reçu, sans le modifier

  // 1. Vérifier la signature : HMAC-SHA256( horodatage + corps ), clé = secret du webhook
  const header = req.headers.get("Wave-Signature") ?? "";
  const timestamp = /(?:^|,)t=(\d+)/.exec(header)?.[1] ?? "";
  const signatures = [...header.matchAll(/v1=([0-9a-f]+)/g)].map((m) => m[1]);
  if (!timestamp || signatures.length === 0) return reply(401, { message: "Signature absente." });
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return reply(401, { message: "Message trop ancien." });
  const expected = await hmacHex(secret, timestamp + raw);
  if (!signatures.some((s) => sameText(s, expected))) return reply(401, { message: "Signature invalide." });

  // 2. Lire l'événement
  let event: { id?: string; type?: string; data?: Record<string, unknown> };
  try { event = JSON.parse(raw); } catch (_) { return reply(400); }
  const data = event.data ?? {};
  const bookingId = String(data.client_reference ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(bookingId)) return reply(200); // pas une de nos réservations

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, secretKey());
  const { data: booking } = await admin.from("bookings").select("*").eq("id", bookingId).maybeSingle();
  if (!booking) return reply(200);

  if (event.type === "checkout.session.completed") {
    // 3. Le montant payé doit être exactement le total de la réservation
    const paid = Number(data.amount);
    const okAmount = Number.isFinite(paid) && paid === booking.total && data.currency === "XOF";
    await admin.from("payments")
      .update({ status: okAmount ? "paid" : "failed", provider_ref: String(data.id ?? "") })
      .eq("booking_id", bookingId).eq("provider", "wave").eq("status", "pending");
    if (!okAmount) {
      console.error("Montant inattendu", bookingId, data.amount, data.currency);
      return reply(200);
    }
    if (booking.status === "pending") {
      await admin.from("bookings").update({ status: "confirmed" }).eq("id", bookingId).eq("status", "pending");
    } else {
      // Réservation déjà annulée ou expirée : le paiement est enregistré, à rembourser à la main.
      console.error("Paiement reçu pour une réservation non en attente", bookingId, booking.status);
    }
  } else if (event.type === "checkout.session.payment_failed") {
    await admin.from("payments").update({ status: "failed" })
      .eq("booking_id", bookingId).eq("provider", "wave").eq("status", "pending");
  }
  return reply(200);
});
