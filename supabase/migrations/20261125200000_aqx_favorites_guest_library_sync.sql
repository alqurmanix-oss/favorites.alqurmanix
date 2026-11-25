create or replace function public.aqx_favorites_merge_guest_to_guest(
  p_source_guest_id uuid,
  p_target_guest_id uuid,
  p_target_recovery_hash text,
  p_new_target_token_hash text
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_source public.aqx_favorites_guest_sessions%rowtype;
  v_target public.aqx_favorites_guest_sessions%rowtype;
  v_table record;
  v_rows bigint := 0;
  v_total bigint := 0;
  v_items bigint := 0;
  v_categories bigint := 0;
  v_collections bigint := 0;
begin
  if p_source_guest_id is null or p_target_guest_id is null
     or p_source_guest_id = p_target_guest_id
     or p_target_recovery_hash is null
     or p_target_recovery_hash !~ '^[a-f0-9]{64}$'
     or p_new_target_token_hash is null
     or p_new_target_token_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'library_sync_parameters_invalid';
  end if;

  perform 1
  from public.aqx_favorites_guest_sessions
  where guest_id in (p_source_guest_id,p_target_guest_id)
  order by guest_id
  for update;

  select * into v_source from public.aqx_favorites_guest_sessions
  where guest_id=p_source_guest_id;
  select * into v_target from public.aqx_favorites_guest_sessions
  where guest_id=p_target_guest_id;

  if v_source.guest_id is null or v_target.guest_id is null then
    raise exception 'library_sync_library_not_found';
  end if;
  if v_source.status <> 'active' or v_source.expires_at <= now() then
    raise exception 'library_sync_source_invalid';
  end if;
  if v_target.status <> 'active' or v_target.expires_at <= now()
     or v_target.recovery_key_hash_hex is distinct from p_target_recovery_hash then
    raise exception 'library_sync_target_invalid';
  end if;

  perform 1 from public.aqx_favorites_items
  where owner_type='guest' and owner_id in (p_source_guest_id,p_target_guest_id)
  for update;

  select count(*) into v_items from public.aqx_favorites_items
  where owner_type='guest' and owner_id=p_source_guest_id;
  select count(*) into v_categories from public.aqx_favorites_categories
  where owner_type='guest' and owner_id=p_source_guest_id;
  select count(*) into v_collections from public.aqx_favorites_collections
  where owner_type='guest' and owner_id=p_source_guest_id;

  -- Merge duplicate active URLs into the destination item; retain the source row as archived history.
  update public.aqx_favorites_items t
  set note=case when coalesce(t.note,'')='' then s.note
                when coalesce(s.note,'')='' then t.note
                else left(t.note||E'\n\n'||s.note,500) end,
      tags=(select coalesce(array_agg(distinct tag),'{}'::text[])
            from unnest(coalesce(t.tags,'{}'::text[])||coalesce(s.tags,'{}'::text[])) tag),
      metadata=coalesce(t.metadata,'{}'::jsonb)||coalesce(s.metadata,'{}'::jsonb),
      updated_at=now()
  from public.aqx_favorites_items s
  where s.owner_type='guest' and s.owner_id=p_source_guest_id
    and t.owner_type='guest' and t.owner_id=p_target_guest_id
    and t.normalized_url=s.normalized_url and t.deleted_at is null and s.deleted_at is null;

  update public.aqx_favorites_items s
  set deleted_at=now(), updated_at=now()
  where s.owner_type='guest' and s.owner_id=p_source_guest_id and s.deleted_at is null
    and exists (
      select 1 from public.aqx_favorites_items t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id
        and t.normalized_url=s.normalized_url and t.deleted_at is null
    );

  -- Avoid name/slug uniqueness collisions while preserving both collections and categories.
  update public.aqx_favorites_collections s
  set name=left(s.name,70)||' [Merged '||substr(s.id::text,1,8)||']'
  where s.owner_type='guest' and s.owner_id=p_source_guest_id and s.deleted_at is null
    and exists (
      select 1 from public.aqx_favorites_collections t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id
        and lower(t.name)=lower(s.name) and t.deleted_at is null
    );

  update public.aqx_favorites_categories s
  set slug=left(s.slug,80)||'-m-'||substr(s.id::text,1,8)
  where s.owner_type='guest' and s.owner_id=p_source_guest_id and s.deleted_at is null
    and exists (
      select 1 from public.aqx_favorites_categories t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id
        and t.slug=s.slug and t.deleted_at is null
    );

  -- Preserve both libraries' saved searches when their names collide.
  update public.aqx_favorites_saved_searches s
  set name=left(s.name,72)||' [Merged '||substr(s.id::text,1,8)||']'
  where s.owner_type='guest' and s.owner_id=p_source_guest_id
    and exists (
      select 1 from public.aqx_favorites_saved_searches t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id and t.name=s.name
    );

  -- Usage is cumulative; combine matching periods.
  insert into public.aqx_favorites_usage(owner_type,owner_id,metric,period_start,period_end,quantity,updated_at)
  select 'guest',p_target_guest_id,metric,period_start,period_end,quantity,now()
  from public.aqx_favorites_usage
  where owner_type='guest' and owner_id=p_source_guest_id
  on conflict (owner_type,owner_id,metric,period_start)
  do update set quantity=public.aqx_favorites_usage.quantity+excluded.quantity,
                period_end=greatest(public.aqx_favorites_usage.period_end,excluded.period_end),
                updated_at=now();
  delete from public.aqx_favorites_usage
  where owner_type='guest' and owner_id=p_source_guest_id;

  update public.aqx_favorites_knowledge_nodes s
  set normalized_label=left(s.normalized_label,460)||' [merged:'||substr(s.id::text,1,8)||']'
  where s.owner_type='guest' and s.owner_id=p_source_guest_id
    and exists (
      select 1 from public.aqx_favorites_knowledge_nodes t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id
        and t.node_type=s.node_type and t.normalized_label=s.normalized_label
    );

  update public.aqx_favorites_entity_merge_candidates s
  set idempotency_key=left(s.idempotency_key,165)||':merged:'||substr(s.id::text,1,8)
  where s.owner_type='guest' and s.owner_id=p_source_guest_id
    and exists (
      select 1 from public.aqx_favorites_entity_merge_candidates t
      where t.owner_type='guest' and t.owner_id=p_target_guest_id
        and t.idempotency_key=s.idempotency_key
    );

  set constraints all deferred;

  for v_table in
    select c.table_name
    from information_schema.columns c
    where c.table_schema='public' and c.column_name in ('owner_type','owner_id')
      and c.table_name like 'aqx_favorites%'
      and c.table_name not in ('aqx_favorites_app_reviews','aqx_favorites_app_review_likes','aqx_favorites_app_review_media')
    group by c.table_name
    having count(*)=2
    order by case c.table_name
      when 'aqx_favorites_categories' then 1
      when 'aqx_favorites_knowledge_nodes' then 2
      else 3 end, c.table_name
  loop
    execute format(
      'update public.%I set owner_id=$1 where owner_type=$2 and owner_id=$3',
      v_table.table_name
    ) using p_target_guest_id,'guest',p_source_guest_id;
    get diagnostics v_rows = row_count;
    v_total := v_total + v_rows;
  end loop;

  -- Rotate the target session credential inside the same transaction as the merge.
  update public.aqx_favorites_guest_sessions
  set token_hash_hex=p_new_target_token_hash, last_activity_at=now()
  where guest_id=p_target_guest_id and status='active';

  -- Keep existing device credentials usable, but bind them to the unified guest.
  update public.aqx_favorites_guest_devices
  set guest_id=p_target_guest_id
  where guest_id=p_source_guest_id;
  update public.aqx_favorites_guest_webauthn_credentials
  set guest_id=p_target_guest_id
  where guest_id=p_source_guest_id;
  delete from public.aqx_favorites_webauthn_challenges
  where guest_id=p_source_guest_id;

  update public.aqx_favorites_guest_sessions
  set status='merged', recovery_key_hash_hex=null, revoked_at=now(), last_activity_at=now()
  where guest_id=p_source_guest_id;

  insert into public.aqx_favorites_events(owner_type,owner_id,event_type,details)
  values ('guest',p_target_guest_id,'imported',
    jsonb_build_object('source_guest_id',p_source_guest_id,'merged_rows',v_total,
      'items',v_items,'categories',v_categories,'collections',v_collections,
      'operation','guest_library_sync'));

  return jsonb_build_object('success',true,'merged_rows',v_total,
    'items',v_items,'categories',v_categories,'collections',v_collections);
end;
$function$;

revoke all on function public.aqx_favorites_merge_guest_to_guest(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.aqx_favorites_merge_guest_to_guest(uuid,uuid,text,text) to service_role;
