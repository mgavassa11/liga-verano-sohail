-- ===== Liga de Tenis Sohail — Supabase Setup =====
-- Project: yrywtwmfkfjsuttbtrco
-- Paste ALL of this in Supabase → SQL Editor → RUN

create table if not exists liga_state (
  id int primary key,
  data jsonb,
  updated_at timestamptz default now()
);

insert into liga_state (id, data) values (1, null)
on conflict (id) do nothing;

alter table liga_state enable row level security;

drop policy if exists "lectura_publica"  on liga_state;
drop policy if exists "insert_publico"   on liga_state;
drop policy if exists "update_publico"   on liga_state;

create policy "lectura_publica" on liga_state for select using (true);
create policy "insert_publico"  on liga_state for insert with check (true);
create policy "update_publico"  on liga_state for update using (true) with check (true);
