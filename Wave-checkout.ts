// Fonction "wave-checkout" : crée un paiement Wave pour UNE réservation.
// Le montant vient de la base de données, jamais de l'application.
// Secrets à créer dans Supabase (Edge Functions > Secrets) :
//   WAVE_API_KEY  : la clé API créée dans le portail Wave Business
//   SITE_URL      : l'adresse du site, ex. https://jeanpenielkonan-cyber.github.io/-ivoire-residences/
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const reply = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return reply(405, { message: "Méthode non autorisée." });

  const waveKey = Deno.env.get("WAVE_API_KEY");
  const siteUrl = Deno.env.get("SITE_URL");
  if (!waveKey || !siteUrl) return reply(503, { message: "Le paiement Wave n’est pas encore activé sur ce site." });

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, secretKey());

  // 1. Qui appelle ? (on vérifie le jeton de connexion du voyageur)
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const { data: auth, error: authError } = await admin.auth.getUser(token);
  if (authError || !auth?.user) return reply(401, { message: "Connectez-vous pour payer." });

  // 2. Quelle réservation ?
  let bookingId = "";
  try { bookingId = String((await req.json()).booking_id ?? ""); } catch (_) { /* vide */ }
  if (!/^[0-9a-f-]{36}$/i.test(bookingId)) return reply(400, { message: "Réservation inconnue." });

  const { data: booking } = await admin.from("bookings").select("*").eq("id", bookingId).maybeSingle();
  if (!booking || booking.client_id !== auth.user.id) return reply(404, { message: "Réservation introuvable." });
  if (booking.status !== "pending") return reply(409, { message: "Cette réservation n’attend plus de paiement." });
  if (!Number.isInteger(booking.total) || booking.total < 100) return reply(400, { message: "Montant invalide." });

  // 3. Créer la session de paiement chez Wave
  const base = siteUrl.replace(/#.*$/, "").replace(/\/?$/, "/");
  const wave = await fetch("https://api.wave.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${waveKey}`, "Content-Type": "application/json" },
