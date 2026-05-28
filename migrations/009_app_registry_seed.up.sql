-- 009_app_registry_seed — Baseline curated app database.
--
-- Seeds the global app registry with the well-known SaaS / media
-- / CDN apps that dominate SME traffic. Domains and IP ranges come
-- from each vendor's published endpoint list (linked via
-- metadata_url); the sync job in internal/service/appdb/sync.go
-- refreshes them on a 24h cadence.
--
-- The seed is idempotent — every INSERT uses ON CONFLICT (name) DO
-- NOTHING so re-running the migration cannot duplicate rows or
-- overwrite operator-curated entries. Operators who need to update
-- a seeded row should use the admin REST API; the seed is the
-- baseline, not the source of truth.

-- ---------------------------------------------------------------------
-- TRUSTED_DIRECT — productivity, identity, IaaS consoles.
-- Direct egress with DNS verification + cert-pin + IP-range
-- binding; no proxy, no TLS decrypt.
-- ---------------------------------------------------------------------

INSERT INTO app_registry (name, vendor, traffic_class, scope, domains, metadata_url, category)
VALUES
    ('Microsoft 365', 'Microsoft', 'trusted_direct', 'global',
     ARRAY['*.office.com', '*.office365.com', '*.microsoft.com', '*.microsoftonline.com',
           '*.outlook.com', '*.sharepoint.com', '*.onedrive.com', 'outlook.office365.com',
           '*.live.com', '*.officeapps.live.com'],
     'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7',
     'productivity'),
    ('Google Workspace', 'Google', 'trusted_direct', 'global',
     ARRAY['*.google.com', '*.googleapis.com', '*.gstatic.com', '*.googleusercontent.com',
           'accounts.google.com', '*.docs.google.com', '*.drive.google.com',
           '*.mail.google.com', '*.gmail.com'],
     'https://www.gstatic.com/ipranges/goog.json',
     'productivity'),
    ('Slack', 'Slack Technologies', 'trusted_direct', 'global',
     ARRAY['*.slack.com', '*.slack-edge.com', '*.slack-files.com', '*.slack-msgs.com',
           '*.slack-imgs.com'],
     NULL,
     'productivity'),
    ('Zoom', 'Zoom Video Communications', 'trusted_direct', 'global',
     ARRAY['*.zoom.us', '*.zoom.com', '*.zoomgov.com', 'zoom.us'],
     'https://assets.zoom.us/docs/ipranges/Zoom.txt',
     'productivity'),
    ('Salesforce', 'Salesforce', 'trusted_direct', 'global',
     ARRAY['*.salesforce.com', '*.force.com', '*.lightning.force.com', '*.visualforce.com',
           '*.cloudforce.com', '*.sforce.com', '*.documentforce.com'],
     'https://help.salesforce.com/articleView?id=000334193',
     'productivity'),
    ('Okta', 'Okta', 'trusted_direct', 'global',
     ARRAY['*.okta.com', '*.oktacdn.com', '*.oktapreview.com', '*.mtls.okta.com'],
     NULL,
     'identity'),
    ('Microsoft Entra ID', 'Microsoft', 'trusted_direct', 'global',
     ARRAY['login.microsoftonline.com', 'login.microsoft.com', 'login.windows.net',
           'graph.microsoft.com', 'login.live.com'],
     NULL,
     'identity'),
    ('AWS Console', 'Amazon Web Services', 'trusted_direct', 'global',
     ARRAY['*.aws.amazon.com', 'console.aws.amazon.com', 'signin.aws.amazon.com',
           '*.signin.aws.amazon.com'],
     'https://ip-ranges.amazonaws.com/ip-ranges.json',
     'iaas'),
    ('Azure Portal', 'Microsoft', 'trusted_direct', 'global',
     ARRAY['portal.azure.com', '*.portal.azure.com', '*.azure.com',
           'management.azure.com'],
     'https://www.microsoft.com/en-us/download/details.aspx?id=56519',
     'iaas'),
    ('GCP Console', 'Google', 'trusted_direct', 'global',
     ARRAY['console.cloud.google.com', '*.cloud.google.com',
           'cloudconsole-app.googleapis.com'],
     NULL,
     'iaas')
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------
-- TRUSTED_MEDIA_BYPASS — high-bandwidth media / CDN that would
-- saturate the proxy. Same safety guarantees as trusted_direct;
-- telemetry is sampled to control cost.
-- ---------------------------------------------------------------------

INSERT INTO app_registry (name, vendor, traffic_class, scope, domains, metadata_url, category)
VALUES
    ('YouTube', 'Google', 'trusted_media_bypass', 'global',
     ARRAY['*.youtube.com', '*.googlevideo.com', '*.ytimg.com', '*.youtu.be',
           '*.ggpht.com'],
     NULL,
     'media'),
    ('Netflix', 'Netflix', 'trusted_media_bypass', 'global',
     ARRAY['*.netflix.com', '*.nflxvideo.net', '*.nflximg.net', '*.nflxso.net',
           '*.nflxext.com'],
     NULL,
     'media'),
    ('Spotify', 'Spotify', 'trusted_media_bypass', 'global',
     ARRAY['*.spotify.com', '*.scdn.co', '*.spotifycdn.com'],
     NULL,
     'media'),
    ('Microsoft Teams Media', 'Microsoft', 'trusted_media_bypass', 'global',
     ARRAY['*.teams.microsoft.com', 'teams.microsoft.com', '*.skype.com',
           '*.skype.net', '*.lync.com'],
     'https://endpoints.office.com/endpoints/worldwide?ServiceAreas=Skype',
     'media'),
    ('Zoom Media', 'Zoom Video Communications', 'trusted_media_bypass', 'global',
     ARRAY['*.zoomgov.com', '*.zoomdev.us', '*.cloud.zoom.us'],
     'https://assets.zoom.us/docs/ipranges/ZoomMeetings.txt',
     'media'),
    ('Apple Updates', 'Apple', 'trusted_media_bypass', 'global',
     ARRAY['*.apple.com', '*.mzstatic.com', '*.cdn-apple.com', 'swcatalog.apple.com',
           'swdist.apple.com', 'swdownload.apple.com', '*.itunes.apple.com'],
     NULL,
     'updates'),
    ('Windows Update', 'Microsoft', 'trusted_media_bypass', 'global',
     ARRAY['*.windowsupdate.com', '*.update.microsoft.com', 'download.windowsupdate.com',
           '*.delivery.mp.microsoft.com', '*.dl.delivery.mp.microsoft.com'],
     NULL,
     'updates'),
    ('Chrome Update', 'Google', 'trusted_media_bypass', 'global',
     ARRAY['*.chromiumdash.appspot.com', 'tools.google.com', 'dl.google.com',
           '*.gvt1.com'],
     NULL,
     'updates')
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------
-- INSPECT_LITE — DNS verification + URL-cat lookup, no TLS decrypt.
-- Top-Alexa, well-known CDNs, banking. We rely on the URL-cat feed
-- to catch bad pages without paying the decrypt cost.
-- ---------------------------------------------------------------------

INSERT INTO app_registry (name, vendor, traffic_class, scope, domains, metadata_url, category)
VALUES
    ('Cloudflare CDN', 'Cloudflare', 'inspect_lite', 'global',
     ARRAY['*.cloudflare.com', '*.cdn.cloudflare.net'],
     'https://www.cloudflare.com/ips-v4',
     'cdn'),
    ('Akamai CDN', 'Akamai', 'inspect_lite', 'global',
     ARRAY['*.akamai.net', '*.akamaihd.net', '*.akamaized.net', '*.akamaiedge.net'],
     NULL,
     'cdn'),
    ('Fastly CDN', 'Fastly', 'inspect_lite', 'global',
     ARRAY['*.fastly.net', '*.fastlylb.net'],
     'https://api.fastly.com/public-ip-list',
     'cdn'),
    ('Amazon CloudFront', 'Amazon Web Services', 'inspect_lite', 'global',
     ARRAY['*.cloudfront.net'],
     'https://ip-ranges.amazonaws.com/ip-ranges.json',
     'cdn'),
    ('GitHub', 'GitHub', 'inspect_lite', 'global',
     ARRAY['github.com', '*.github.com', '*.githubusercontent.com', '*.github.io',
           '*.githubassets.com'],
     'https://api.github.com/meta',
     'developer'),
    ('Stack Overflow', 'Stack Exchange', 'inspect_lite', 'global',
     ARRAY['*.stackoverflow.com', '*.stackexchange.com', '*.sstatic.net'],
     NULL,
     'developer'),
    ('LinkedIn', 'Microsoft', 'inspect_lite', 'global',
     ARRAY['*.linkedin.com', '*.licdn.com'],
     NULL,
     'social'),
    ('Bank of America', 'Bank of America', 'inspect_lite', 'global',
     ARRAY['*.bankofamerica.com', 'bankofamerica.com'],
     NULL,
     'finance'),
    ('Chase Bank', 'JPMorgan Chase', 'inspect_lite', 'global',
     ARRAY['*.chase.com', 'chase.com'],
     NULL,
     'finance'),
    ('Wells Fargo', 'Wells Fargo', 'inspect_lite', 'global',
     ARRAY['*.wellsfargo.com', 'wellsfargo.com'],
     NULL,
     'finance'),
    ('HSBC', 'HSBC', 'inspect_lite', 'global',
     ARRAY['*.hsbc.com', 'hsbc.com', '*.hsbc.co.uk'],
     NULL,
     'finance')
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------------
-- Regional apps.
-- ---------------------------------------------------------------------

INSERT INTO app_registry (name, vendor, traffic_class, scope, regions, domains, category)
VALUES
    -- APAC
    ('LINE', 'LY Corporation', 'trusted_direct', 'regional',
     ARRAY['APAC', 'JP', 'TW', 'TH'],
     ARRAY['*.line.me', '*.line-apps.com', '*.line-scdn.net', '*.naver.jp'],
     'messaging'),
    ('WeChat', 'Tencent', 'trusted_direct', 'regional',
     ARRAY['APAC', 'CN', 'HK'],
     ARRAY['*.wechat.com', '*.weixin.qq.com', '*.wx.qq.com', 'wx.qq.com'],
     'messaging'),
    ('KakaoTalk', 'Kakao', 'trusted_direct', 'regional',
     ARRAY['APAC', 'KR'],
     ARRAY['*.kakao.com', '*.kakaocdn.net', '*.daum.net'],
     'messaging'),
    ('Grab', 'Grab Holdings', 'inspect_lite', 'regional',
     ARRAY['APAC', 'SG', 'MY', 'TH', 'ID', 'VN', 'PH'],
     ARRAY['*.grab.com', '*.grabtaxi.com', '*.grabpay.com'],
     'mobility'),
    ('Gojek', 'GoTo Group', 'inspect_lite', 'regional',
     ARRAY['APAC', 'ID', 'SG'],
     ARRAY['*.gojek.com', '*.go-jek.com', '*.gopayapi.com'],
     'mobility'),
    -- EU
    ('GOV.UK', 'UK Government', 'inspect_lite', 'regional',
     ARRAY['EU', 'GB'],
     ARRAY['*.gov.uk', 'gov.uk'],
     'government'),
    ('Bundesregierung (DE)', 'German Federal Government', 'inspect_lite', 'regional',
     ARRAY['EU', 'DE'],
     ARRAY['*.bund.de', 'bund.de'],
     'government'),
    ('Deutsche Bank', 'Deutsche Bank', 'inspect_lite', 'regional',
     ARRAY['EU', 'DE'],
     ARRAY['*.deutsche-bank.de', '*.db.com'],
     'finance'),
    -- ANZ
    ('MyGov (AU)', 'Australian Government', 'inspect_lite', 'regional',
     ARRAY['ANZ', 'AU'],
     ARRAY['*.my.gov.au', 'my.gov.au', '*.servicesaustralia.gov.au'],
     'government'),
    ('Commonwealth Bank (AU)', 'Commonwealth Bank', 'inspect_lite', 'regional',
     ARRAY['ANZ', 'AU'],
     ARRAY['*.commbank.com.au', 'commbank.com.au'],
     'finance'),
    ('Westpac (AU)', 'Westpac', 'inspect_lite', 'regional',
     ARRAY['ANZ', 'AU'],
     ARRAY['*.westpac.com.au', 'westpac.com.au'],
     'finance'),
    ('ANZ Bank', 'ANZ Banking Group', 'inspect_lite', 'regional',
     ARRAY['ANZ', 'AU', 'NZ'],
     ARRAY['*.anz.com', 'anz.com', '*.anz.co.nz'],
     'finance')
ON CONFLICT (name) DO NOTHING;
