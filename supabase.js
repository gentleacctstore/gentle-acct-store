const SUPABASE_URL =
  "https://fbeibzungcyhcgmidpw.supabase.co";

const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_6eVFrykVcHc6OQOcPhH3Fg_WQbAe7u3";

window.supabaseClient =
  window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY
  );