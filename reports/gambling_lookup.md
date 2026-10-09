# Gambling lookup files

Built by `src/gambling_lookup.py` from the 2026-10-09 snapshots (UT1 sha256 `9f21a3a77811`, Blocklist Project `d583202e86eb`). Gambling *category*, not a scam verdict. Strings only.

## `data/final/gambling_domains.tsv`

- 362,444 registered domains: both lists 25,977, UT1 only 21,474, Blocklist Project only 314,993
- **Tranco rule:** a Blocklist-Project-only hit in the Tranco top 10,000 is ignored (a lone hit from the auto-aggregated list on a popular site) unless the registered domain contains a gambling token (`bet|casino|satta|sattaking|dpboss|poker|slot|rummy`). 85 domains fall under the rule: **19 come back** (token in the name), **66 stay ignored**. Both groups are listed at the end.
- **still in, in the Tranco top 10,000:** 74 on both lists, 11 on UT1 only and 19 Blocklist-Project-only (token exception); the `tranco_rank` column lets the engine tighten this without a rebuild. Highest ranked, both lists: b-cdn.net, wordpress.com, onelink.me, okta.com, free.fr, mundodeportivo.com, nesine.com, betway.co.za, forebet.com, casinoplus.com.ph, caliente.mx, flashscore.fr, betano.pe, betpawa.ug. Several are general platforms (wordpress.com, okta.com, b-cdn.net ...), so a list hit on a top-ranked domain is weak evidence; that is the Links ladder's rule to set.

## `data/final/gambling_platform_hosts.tsv`

- 1,338 host-level entries on hosting platforms (61 suffixes, e.g. com.de, co.nl, msk.su, cloudfront.net, pages.dev, co.com), kept out of the registered-domain set above.

## `data/final/gambling_india.json`

- seed domains: 101 (101 from the lists, 0 from the manual review; the 16 India-flavoured review domains join once marked `gambling_spam`)
- rule: strong tokens ['satta', 'sattaking', 'dpboss'], weak tokens ['matka', 'kalyan'] (never on their own), exempt suffixes ['gov.in', 'nic.in', 'edu.in', 'ac.in', 'res.in'], allow-list ['jansatta.com', 'loksatta.com', 'sattacademy.com'] (the three false positives found in the Tranco top 100k)
- Tranco top 100k: **78 strong matches**, 21 weak-only. Weak-only domains are about two thirds gambling by eye (matka420.in, matka420.live, matkafasi.com, kalyanjewellers.net, aurinkomatkat.fi, matkaji.net, matkavip.com, amarmatka.co, appamatka.in, bossmatka.me, chartkalyan.co.in, kalyanjewellers.company ...), which is why they never match alone.
- urls.csv reg_domains hit by the rule (strong / weak) by label and provenance: {('strong', 'benign', 'pending_review'): 17, ('strong', 'gambling_spam', 'list_confirmed'): 1, ('weak', 'benign', 'pending_review'): 1, ('weak', 'phishing', 'source_label'): 2}
- Recall caveat: the rule only sees names with these tokens; it measures nothing about Indian gambling sites with other names (cricket / IPL / colour-prediction apps ...).

## Came back through the token exception (19)

hollywoodbets.net (1,361), sportybet.com (1,396), betika.com (1,640), betking.com (1,748), triunfobet.com (1,784), betcity.ru (3,863), superbet.ro (5,475), goldbet.it (8,300), betpawa.com (8,585), supersportbet.com (8,671), takbet.com (8,699), melbetegypt.com (8,760), jugabet.cl (8,861), betflag.it (9,027), okbet.com (9,073), odibets.com (9,204), betpawa.co.tz (9,257), micasino.com (9,267), crystalbet.com (9,587)

## Still omitted from the domain lookup (66)

tumblr.com (156), paytmfirstgames.com (186), omtrdc.net (255), weebly.com (339), zendesk.com (372), substack.com (450), ampproject.org (479), rakuten.co.jp (574), bandcamp.com (731), lefigaro.fr (829), ay267.com (1,225), netkeiba.com (1,322), edna.ru (1,418), evo-games.com (1,471), bingoplus.com (1,654), nustargame.com (1,655), jra.go.jp (1,668), ptgaming.ph (1,704), takarakuji-official.jp (1,718), arionplay.com (1,732), business.site (2,116), salesforceliveagent.com (2,140), adsco.re (2,159), garena.com (2,341), jimdofree.com (2,419), web.de (2,481), gmx.net (2,501), polymarket.com (2,502), dtscout.com (2,532), sportradar.com (2,747), softonic.com (3,049), mystrikingly.com (3,263), gitbook.io (3,438), jimdosite.com (3,576), skyvegas.com (3,623), 365scores.com (4,112), a-ads.com (4,150), aiscore.com (5,442), championat.com (5,804), webim.ru (6,267), sportinglife.com (6,723), attheraces.com (7,144), pump.fun (7,224), firebasedatabase.app (7,445), msport.com (7,644), sportingnews.com (7,947), pocketoption.com (7,977), sportpesa.com (8,165), kalshi.com (8,275), loteriasyapuestas.es (8,644), photoshelter.com (8,973), gzone.ph (8,983), lotteryusa.com (9,088), qxbroker.com (9,110), szerencsejatek.hu (9,209), apuestasroyal.com (9,359), cv666.net (9,366), gogoroyal.com (9,421), kdreams.jp (9,513), juegosonce.es (9,533), 789bingo.com (9,574), juan365.com (9,733), ninogaming.com (9,773), ph365.org (9,785), keiba.go.jp (9,827), tippmix.hu (9,934)
