package graph

// https://gist.github.com/michenriksen/8710649
// Keep sorted
var emailBlacklist []string = []string{
	"0815.ru",
	"0815.ru",
	"0hio0ak.com",
	"0wnd.net",
	"0wnd.org",
	"10minutemail.co.za",
	"10minutemail.com",
	"123-m.com",
	"1fsdfdsfsdf.tk",
	"1mail.x24hr.com",
	"1pad.de",
	"1secmail.com",
	"1secmail.net",
	"1secmail.org",
	"20minutemail.com",
	"21cn.com",
	"23.8.dnsabr.com",
	"2fdgdfgdfgdf.tk",
	"2prong.com",
	"30minutemail.com",
	"32core.live",
	"33mail.com",
	"3trtretgfrfe.tk",
	"4dentalsolutions.com",
	"4gfdsgfdgfd.tk",
	"4warding.com",
	"5ghgfhfghfgh.tk",
	"6hjgjhgkilkj.tk",
	"6paq.com",
	"7tags.com",
	"8.dnsabr.com",
	"888.dnS-clouD.NET",
	"99email.xyz",
	"9ox.net",
	"B.cr.cloUdnS.asia",
	"BD.dns-cloud.net",
	"CR.cloudns.asia",
	"DVD.dns-cloud.net",
	"DVD.dnsabr.com",
	"Disposable.ml",
	"MSFT.cloudns.asia",
	"SHIT.dns-cloud.net",
	"SHIT.dnsabr.com",
	"TLS.cloudns.asia",
	"YX.dns-cloud.net",
	"a-bc.net",
	"adult-work.info",
	"agedmail.com",
	"ama-trade.de",
	"amilegit.com",
	"amiri.net",
	"amiriindustries.com",
	"anonmails.de",
	"anonymbox.com",
	"anonymized.org",
	"antichef.com",
	"antichef.net",
	"antireg.ru",
	"antispam.de",
	"antispammail.de",
	"armyspy.com",
	"artman-conception.com",
	"asia.dnsabr.com",
	"awdrt.net",
	"azmeil.tk",
	"badlion.co.uk",
	"baxomale.ht.cx",
	"beefmilk.com",
	"bigstring.com",
	"binkmail.com",
	"bio-muesli.net",
	"biyac.com",
	"blackturtle.xyz",
	"bobmail.info",
	"bodhi.lawlita.com",
	"bofthew.com",
	"bootybay.de",
	"boun.cr",
	"bouncr.com",
	"breakthru.com",
	"brefmail.com",
	"bsnow.net",
	"bspamfree.org",
	"btc.glass",
	"budaya-tionghoa.com",
	"budayationghoa.com",
	"bugmenot.com",
	"bund.us",
	"burstmail.info",
	"buymoreplays.com",
	"byom.de",
	"c2.hu",
	"card.zp.ua",
	"casualdx.com",
	"cek.pm",
	"centermail.com",
	"centermail.net",
	"chammy.info",
	"chapedia.net",
	"chapedia.org",
	"chasefreedomactivate.com",
	"childsavetrust.org",
	"chitthi.in",
	"chogmail.com",
	"choicemail1.com",
	"clixser.com",
	"cmail.net",
	"cmail.org",
	"coldemail.info",
	"cool.fr.nf",
	"coolmailcool.com",
	"corona.is.bullsht.dedyn.io",
	"courriel.fr.nf",
	"courrieltemporaire.com",
	"cpmail.life",
	"crapmail.org",
	"cust.in",
	"cuvox.de",
	"d3p.dk",
	"dacoolest.com",
	"dandikmail.com",
	"dayrep.com",
	"dcemail.com",
	"deadaddress.com",
	"deadspam.com",
	"delikkt.de",
	"despam.it",
	"despammed.com",
	"devnullmail.com",
	"dfgh.net",
	"digitalsanctuary.com",
	"dingbone.com",
	"discard.email",
	"discardmail.com",
	"discardmail.de",
	"disposable-email.ml",
	"disposableaddress.com",
	"disposableemailaddresses.com",
	"disposableinbox.com",
	"dispose.it",
	"dispostable.com",
	"dodgeit.com",
	"dodgit.com",
	"donemail.ru",
	"dontreg.com",
	"dontsendmespam.de",
	"drdrb.net",
	"dristypat.com",
	"dump-email.info",
	"dumpandjunk.com",
	"dumpyemail.com",
	"e-mail.com",
	"e-mail.org",
	"e4ward.com",
	"easytrashmail.com",
	"einmalmail.de",
	"einrot.com",
	"eintagsmail.de",
	"emailgo.de",
	"emailias.com",
	"emaillime.com",
	"emailsensei.com",
	"emailtemporanea.com",
	"emailtemporanea.net",
	"emailtemporar.ro",
	"emailtemporario.com.br",
	"emailthe.net",
	"emailtmp.com",
	"emailwarden.com",
	"emailx.at.hm",
	"emailxfer.com",
	"emeil.in",
	"emeil.ir",
	"emz.net",
	"ero-tube.org",
	"eu.dns-cloud.net",
	"eu.dnsabr.com",
	"evopo.com",
	"explodemail.com",
	"express.net.ua",
	"eyepaste.com",
	"fakeinbox.com",
	"fakeinformation.com",
	"fansworldwide.de",
	"fantasymail.de",
	"fexbos.ru",
	"fexbox.org",
	"fexpost.com",
	"fightallspam.com",
	"filzmail.com",
	"fivemail.de",
	"fleckens.hu",
	"fouadps.cf",
	"frapmail.com",
	"freundin.ru",
	"friendlymail.co.uk",
	"from.onmypc.info",
	"fshare.ootech.vn",
	"fuckingduh.com",
	"fudgerub.com",
	"fyii.de",
	"garliclife.com",
	"gehensiemirnichtaufdensack.de",
	"geneseeit.com",
	"get2mail.fr",
	"getairmail.com",
	"getmails.eu",
	"getonemail.com",
	"giantmail.de",
	"girlsundertheinfluence.com",
	"gishpuppy.com",
	"gmaile.design",
	"gmial.com",
	"goemailgo.com",
	"gotmail.net",
	"gotmail.org",
	"gotti.otherinbox.com",
	"great-host.in",
	"greensloth.com",
	"grr.la",
	"gsrv.co.uk",
	"guerillamail.biz",
	"guerillamail.com",
	"guerrillamail.biz",
	"guerrillamail.com",
	"guerrillamail.de",
	"guerrillamail.info",
	"guerrillamail.net",
	"guerrillamail.org",
	"guerrillamailblock.com",
	"gustr.com",
	"harakirimail.com",
	"hat-geld.de",
	"hatespam.org",
	"herp.in",
	"hidemail.de",
	"hidemyass.fun",
	"hidzz.com",
	"historictheology.com",
	"hmamail.com",
	"hopemail.biz",
	"hostux.ninja",
	"ieh-mail.de",
	"igosad.tech",
	"ikbenspamvrij.nl",
	"imails.info",
	"inbax.tk",
	"inbox.si",
	"inboxalias.com",
	"inboxclean.com",
	"inboxclean.org",
	"infocom.zp.ua",
	"inpwa.com",
	"instant-mail.de",
	"intopwa.com",
	"intopwa.net",
	"intopwa.org",
	"ip6.li",
	"irish2me.com",
	"iwi.net",
	"jetable.com",
	"jetable.fr.nf",
	"jetable.net",
	"jetable.org",
	"jnxjn.com",
	"jourrapide.com",
	"jsrsolutions.com",
	"kaaaxcreators.tk",
	"kasmail.com",
	"kaspop.com",
	"ketoblazepro.com",
	"killmail.com",
	"killmail.net",
	"kittenemail.xyz",
	"klassmaster.com",
	"klzlk.com",
	"knol-power.nl",
	"kost.party",
	"koszmail.pl",
	"kurzepost.de",
	"lajoska.pe.hu",
	"lawlita.com",
	"letthemeatspam.com",
	"lhsdv.com",
	"lifebyfood.com",
	"link2mail.net",
	"litedrop.com",
	"lol.ovpn.to",
	"lolfreak.net",
	"lookugly.com",
	"lortemail.dk",
	"lr78.com",
	"lroid.com",
	"lukop.dk",
	"m.cloudns.cl",
	"m21.cc",
	"maa.567map.xyz",
	"mail-filter.com",
	"mail-temporaire.fr",
	"mail.by",
	"mail.igosad.me",
	"mail.kaaaxcreators.tk",
	"mail.mezimages.net",
	"mail.mrgamin.ml",
	"mail.zp.ua",
	"mail1a.de",
	"mail21.cc",
	"mail2rss.org",
	"mail333.com",
	"mailbidon.com",
	"mailbiz.biz",
	"mailblocks.com",
	"mailbox.in.ua",
	"mailbucket.org",
	"mailcat.biz",
	"mailcatch.com",
	"mailde.de",
	"mailde.info",
	"maildrop.cc",
	"maileimer.de",
	"mailexpire.com",
	"mailfa.tk",
	"mailforspam.com",
	"mailfreeonline.com",
	"mailg.ml",
	"mailguard.me",
	"mailin8r.com",
	"mailinater.com",
	"mailinator.com",
	"mailinator.net",
	"mailinator.org",
	"mailinator2.com",
	"mailincubator.com",
	"mailismagic.com",
	"mailme.lv",
	"mailme24.com",
	"mailmetrash.com",
	"mailmoat.com",
	"mailms.com",
	"mailnesia.com",
	"mailnull.com",
	"mailorg.org",
	"mailpick.biz",
	"mailrock.biz",
	"mailscrap.com",
	"mailshell.com",
	"mailsiphon.com",
	"mailtemp.info",
	"mailto.plus",
	"mailtome.de",
	"mailtothis.com",
	"mailtrash.net",
	"mailtv.net",
	"mailtv.tv",
	"mailzilla.com",
	"makemetheking.com",
	"manybrain.com",
	"mbx.cc",
	"meantinc.com",
	"media.motornation.buzz",
	"mega.zik.dj",
	"meinspamschutz.de",
	"meltmail.com",
	"messagebeamer.de",
	"mezimages.net",
	"ministry-of-silly-walks.de",
	"mintemail.com",
	"misterpinball.de",
	"miucce.com",
	"mm.8.dnsabr.com",
	"moncourrier.fr.nf",
	"monemail.fr.nf",
	"monmail.fr.nf",
	"monumentmail.com",
	"mowgli.jungleheart.com",
	"mrdeeps.ml",
	"mrgamin.cf",
	"mrgamin.gq",
	"mrgamin.ml",
	"mt2009.com",
	"mt2014.com",
	"mycard.net.ua",
	"mycleaninbox.net",
	"mymail-in.net",
	"mypacks.net",
	"mypartyclip.de",
	"myphantomemail.com",
	"mysamp.de",
	"mytempemail.com",
	"mytempmail.com",
	"mytrashmail.com",
	"nabuma.com",
	"neomailbox.com",
	"nepwk.com",
	"nervmich.net",
	"nervtmich.net",
	"netmails.com",
	"netmails.net",
	"neverbox.com",
	"nice-4u.com",
	"nincsmail.hu",
	"nnh.com",
	"no-spam.ws",
	"noblepioneer.com",
	"nomail.pw",
	"nomail.xl.cx",
	"nomail2me.com",
	"nomorespamemails.com",
	"nospam.ze.tc",
	"nospam4.us",
	"nospamfor.us",
	"nospammail.net",
	"notmailinator.com",
	"notmyemail.tech",
	"now.mefound.com",
	"nowhere.org",
	"nowmymail.com",
	"nucleant.org",
	"nurfuerspam.de",
	"nus.edu.sg",
	"objectmail.com",
	"obobbo.com",
	"odnorazovoe.ru",
	"ondemandemail.top",
	"oneoffemail.com",
	"onewaymail.com",
	"onlatedotcom.info",
	"online.ms",
	"opayq.com",
	"ordinaryamerican.net",
	"otherinbox.com",
	"ovpn.to",
	"owlpic.com",
	"pancakemail.com",
	"pcusers.otherinbox.com",
	"pecinan.com",
	"pecinan.net",
	"pecinan.org",
	"pflege-schoene-haut.de",
	"pjjkp.com",
	"plexolan.de",
	"poczta.onet.pl",
	"politikerclub.de",
	"poofy.org",
	"pookmail.com",
	"postheo.de",
	"powerencry.com",
	"privacy.net",
	"privatdemail.net",
	"proxymail.eu",
	"prtnx.com",
	"putthisinyourspamdatabase.com",
	"putthisinyourspamdatabase.com",
	"pw.8.dnsabr.com",
	"pw.epac.to",
	"qq.com",
	"qq.com",
	"quickinbox.com",
	"rcpt.at",
	"reallymymail.com",
	"realtyalerts.ca",
	"recode.me",
	"recursor.net",
	"relay.firefox.com",
	"reliable-mail.com",
	"rhyta.com",
	"rmqkr.net",
	"rover.info",
	"royal.net",
	"rtrtr.com",
	"s0ny.net",
	"s0ny.net",
	"safe-mail.net",
	"safeemail.xyz",
	"safersignup.de",
	"safetymail.info",
	"safetypost.de",
	"saynotospams.com",
	"schafmail.de",
	"schrott-email.de",
	"secretemail.de",
	"secure-mail.biz",
	"senseless-entertainment.com",
	"services391.com",
	"sexy.camdvr.org",
	"sharklasers.com",
	"shieldemail.com",
	"shiftmail.com",
	"shitmail.me",
	"shitware.nl",
	"shmeriously.com",
	"shortmail.net",
	"sibmail.com",
	"sinnlos-mail.de",
	"slapsfromlastnight.com",
	"slaskpost.se",
	"smack.email",
	"smashmail.de",
	"smashmail.de",
	"smellfear.com",
	"snakemail.com",
	"sneakemail.com",
	"sneakmail.de",
	"snkmail.com",
	"sofimail.com",
	"sogetthis.com",
	"solpatu.space",
	"solvemail.info",
	"soodonims.com",
	"spam4.me",
	"spamail.de",
	"spamarrest.com",
	"spambob.net",
	"spambog.com",
	"spambog.de",
	"spambog.ru",
	"spambog.ru",
	"spambox.us",
	"spamcannon.com",
	"spamcannon.net",
	"spamcon.org",
	"spamcorptastic.com",
	"spamcowboy.com",
	"spamcowboy.net",
	"spamcowboy.org",
	"spamday.com",
	"spamex.com",
	"spamfree.eu",
	"spamfree24.com",
	"spamfree24.de",
	"spamfree24.org",
	"spamgoes.in",
	"spamgourmet.com",
	"spamgourmet.net",
	"spamgourmet.org",
	"spamherelots.com",
	"spamherelots.com",
	"spamhereplease.com",
	"spamhereplease.com",
	"spamhole.com",
	"spamify.com",
	"spaml.de",
	"spammotel.com",
	"spamobox.com",
	"spamslicer.com",
	"spamspot.com",
	"spamthis.co.uk",
	"spamtroll.net",
	"speed.1s.fr",
	"speedfocus.biz",
	"spoofmail.de",
	"ssl.tls.cloudns.ASIA",
	"stuffmail.de",
	"super-auswahl.de",
	"supergreatmail.com",
	"supermailer.jp",
	"superrito.com",
	"superstachel.de",
	"suremail.info",
	"sweetxxx.de",
	"t.woeishyang.com",
	"talkinator.com",
	"techwizardent.me",
	"teewars.org",
	"teleworm.com",
	"teleworm.us",
	"temp-mail.org",
	"temp-mail.ru",
	"tempe-mail.com",
	"tempemail.co.za",
	"tempemail.com",
	"tempemail.info",
	"tempemail.net",
	"tempemail.net",
	"tempes.gq",
	"tempinbox.co.uk",
	"tempinbox.com",
	"tempmail.eu",
	"tempmail.wizardmail.tech",
	"tempmaildemo.com",
	"tempmailer.com",
	"tempmailer.de",
	"tempomail.fr",
	"temporary-mail.net",
	"temporaryemail.net",
	"temporaryforwarding.com",
	"temporaryinbox.com",
	"temporarymailaddress.com",
	"tempr.email",
	"tempthe.net",
	"thankyou2010.com",
	"thc.st",
	"thelimestones.com",
	"thisisnotmyrealemail.com",
	"thismail.net",
	"throwawayemailaddress.com",
	"tilien.com",
	"tittbit.in",
	"tizi.com",
	"tmailinator.com",
	"tokyoto.site",
	"toomail.biz",
	"topranklist.de",
	"tradermail.info",
	"trap-mail.de",
	"trash-mail.at",
	"trash-mail.com",
	"trash-mail.de",
	"trash2009.com",
	"trashdevil.com",
	"trashemail.de",
	"trashmail.at",
	"trashmail.com",
	"trashmail.de",
	"trashmail.me",
	"trashmail.net",
	"trashmail.org",
	"trashymail.com",
	"trialmail.de",
	"trillianpro.com",
	"truthfinderlogin.com",
	"twinmail.de",
	"twitter-sign-in.cf",
	"tyldd.com",
	"uggsrock.com",
	"umail.net",
	"upived.o",
	"uroid.com",
	"us.af",
	"venompen.com",
	"veryrealemail.com",
	"viditag.com",
	"viralplays.com",
	"virtual-generations.com",
	"vpn.st",
	"vsimcard.com",
	"vubby.com",
	"wasteland.rfc822.org",
	"webemail.me",
	"weg-werf-email.de",
	"wegwerf-emails.de",
	"wegwerfadresse.de",
	"wegwerfemail.com",
	"wegwerfemail.de",
	"wegwerfmail.de",
	"wegwerfmail.info",
	"wegwerfmail.net",
	"wegwerfmail.org",
	"wellsfargocomcardholders.com",
	"wh4f.org",
	"whyspam.me",
	"willhackforfood.biz",
	"willselfdestruct.com",
	"winemaven.info",
	"wronghead.com",
	"www.e4ward.com",
	"www.mailinator.com",
	"wwwnew.eu",
	"x.ip6.li",
	"xagloo.com",
	"xemaps.com",
	"xents.com",
	"xmaily.com",
	"xoxy.net",
	"yep.it",
	"yogamaven.com",
	"yopmail.com",
	"yopmail.fr",
	"yopmail.net",
	"you.has.dating",
	"yourdomain.com",
	"yuurok.com",
	"z1p.biz",
	"za.com",
	"zehnminuten.de",
	"zehnminutenmail.de",
	"zippymail.info",
	"zoemail.net",
	"zomg.info",
}

// https://github.com/marteinn/The-Big-Username-Blacklist
// Keep sorted
var usernameBlacklist []string = []string{
	".htaccess",
	".htpasswd",
	".well_known",
	"400",
	"401",
	"403",
	"404",
	"405",
	"406",
	"407",
	"408",
	"409",
	"410",
	"411",
	"412",
	"413",
	"414",
	"415",
	"416",
	"417",
	"421",
	"422",
	"423",
	"424",
	"426",
	"428",
	"429",
	"431",
	"500",
	"501",
	"502",
	"503",
	"504",
	"505",
	"506",
	"507",
	"508",
	"509",
	"510",
	"511",
	"about",
	"about_us",
	"abuse",
	"access",
	"account",
	"accounts",
	"ad",
	"add",
	"admin",
	"administration",
	"administrator",
	"ads",
	"advertise",
	"advertising",
	"aes128_ctr",
	"aes128_gcm",
	"aes192_ctr",
	"aes256_ctr",
	"aes256_gcm",
	"affiliate",
	"affiliates",
	"ajax",
	"alert",
	"alerts",
	"alpha",
	"amp",
	"analytics",
	"api",
	"app",
	"apps",
	"asc",
	"assets",
	"atom",
	"auth",
	"authentication",
	"authorize",
	"autoconfig",
	"autodiscover",
	"avatar",
	"backup",
	"banner",
	"banners",
	"beta",
	"billing",
	"billings",
	"blog",
	"blogs",
	"board",
	"bookmark",
	"bookmarks",
	"broadcasthost",
	"business",
	"buy",
	"cache",
	"calendar",
	"campaign",
	"captcha",
	"careers",
	"cart",
	"cas",
	"categories",
	"category",
	"cdn",
	"cgi",
	"cgi_bin",
	"chacha20_poly1305",
	"change",
	"channel",
	"channels",
	"chart",
	"chat",
	"checkout",
	"clear",
	"client",
	"close",
	"cms",
	"com",
	"comment",
	"comments",
	"community",
	"compare",
	"compose",
	"config",
	"connect",
	"contact",
	"contest",
	"cookies",
	"copy",
	"copyright",
	"count",
	"create",
	"crossdomain.xml",
	"css",
	"curve25519_sha256",
	"customer",
	"customers",
	"customize",
	"dashboard",
	"db",
	"ddevault",
	"deals",
	"debug",
	"delete",
	"desc",
	"dev",
	"developer",
	"developers",
	"diffie_hellman_group14_sha1",
	"diffie_hellman_group_exchange_sha256",
	"disconnect",
	"discuss",
	"dns",
	"dns0",
	"dns1",
	"dns2",
	"dns3",
	"dns4",
	"docs",
	"documentation",
	"domain",
	"download",
	"downloads",
	"downvote",
	"draft",
	"drop",
	"ecdh_sha2_nistp256",
	"ecdh_sha2_nistp384",
	"ecdh_sha2_nistp521",
	"edit",
	"editor",
	"email",
	"enterprise",
	"error",
	"errors",
	"event",
	"events",
	"example",
	"exception",
	"exit",
	"explore",
	"export",
	"extensions",
	"false",
	"family",
	"faq",
	"faqs",
	"favicon.ico",
	"features",
	"feed",
	"feedback",
	"feeds",
	"file",
	"files",
	"filter",
	"follow",
	"follower",
	"followers",
	"following",
	"fonts",
	"forgot",
	"forgot_password",
	"forgotpassword",
	"form",
	"forms",
	"forum",
	"forums",
	"friend",
	"friends",
	"ftp",
	"get",
	"git",
	"go",
	"group",
	"groups",
	"guest",
	"guidelines",
	"guides",
	"head",
	"header",
	"help",
	"hide",
	"hmac_sha",
	"hmac_sha1",
	"hmac_sha1_etm",
	"hmac_sha2_256",
	"hmac_sha2_256_etm",
	"hmac_sha2_512",
	"hmac_sha2_512_etm",
	"home",
	"host",
	"hosting",
	"hostmaster",
	"htpasswd",
	"http",
	"httpd",
	"https",
	"humans.txt",
	"icons",
	"images",
	"imap",
	"img",
	"import",
	"info",
	"insert",
	"investors",
	"invitations",
	"invite",
	"invites",
	"invoice",
	"is",
	"isatap",
	"issues",
	"it",
	"jobs",
	"join",
	"js",
	"json",
	"keybase.txt",
	"learn",
	"legal",
	"license",
	"licensing",
	"limit",
	"live",
	"load",
	"local",
	"localdomain",
	"localhost",
	"lock",
	"login",
	"logout",
	"lost_password",
	"mail",
	"mail0",
	"mail1",
	"mail2",
	"mail3",
	"mail4",
	"mail5",
	"mail6",
	"mail7",
	"mail8",
	"mail9",
	"mailer_daemon",
	"mailerdaemon",
	"map",
	"marketing",
	"marketplace",
	"master",
	"me",
	"media",
	"member",
	"members",
	"message",
	"messages",
	"metrics",
	"mis",
	"mobile",
	"moderator",
	"modify",
	"more",
	"mx",
	"my",
	"net",
	"network",
	"new",
	"news",
	"newsletter",
	"newsletters",
	"next",
	"nil",
	"no_reply",
	"nobody",
	"noc",
	"none",
	"noreply",
	"notification",
	"notifications",
	"ns",
	"ns0",
	"ns1",
	"ns2",
	"ns3",
	"ns4",
	"ns5",
	"ns6",
	"ns7",
	"ns8",
	"ns9",
	"null",
	"oauth",
	"oauth2",
	"offer",
	"offers",
	"online",
	"openid",
	"order",
	"orders",
	"overview",
	"owner",
	"page",
	"pages",
	"partners",
	"passwd",
	"password",
	"pay",
	"payment",
	"payments",
	"photo",
	"photos",
	"pixel",
	"plans",
	"plugins",
	"policies",
	"policy",
	"pop",
	"pop3",
	"popular",
	"portfolio",
	"post",
	"postfix",
	"postmaster",
	"poweruser",
	"preferences",
	"premium",
	"press",
	"previous",
	"pricing",
	"print",
	"privacy",
	"privacy_policy",
	"private",
	"prod",
	"product",
	"production",
	"profile",
	"profiles",
	"project",
	"projects",
	"public",
	"purchase",
	"put",
	"quota",
	"redirect",
	"reduce",
	"refund",
	"refunds",
	"register",
	"registration",
	"remove",
	"replies",
	"reply",
	"report",
	"request",
	"request_password",
	"reset",
	"reset_password",
	"response",
	"return",
	"returns",
	"review",
	"reviews",
	"robots.txt",
	"root",
	"rootuser",
	"rsa_sha2_2",
	"rsa_sha2_512",
	"rss",
	"rules",
	"sales",
	"save",
	"script",
	"sdk",
	"search",
	"secure",
	"security",
	"select",
	"services",
	"session",
	"sessions",
	"settings",
	"setup",
	"share",
	"shift",
	"shop",
	"signin",
	"signup",
	"sircmpwn",
	"sirhat",
	"sirhit",
	"site",
	"sitemap",
	"sites",
	"smtp",
	"sort",
	"source",
	"sourcehut",
	"sql",
	"srcht",
	"srchut",
	"srht",
	"ssh",
	"ssh_rsa",
	"ssl",
	"ssladmin",
	"ssladministrator",
	"sslwebmaster",
	"stage",
	"staging",
	"stat",
	"static",
	"statistics",
	"stats",
	"status",
	"store",
	"style",
	"styles",
	"stylesheet",
	"stylesheets",
	"subdomain",
	"subscribe",
	"sudo",
	"super",
	"superuser",
	"support",
	"survey",
	"sync",
	"sysadmin",
	"system",
	"tablet",
	"tag",
	"tags",
	"team",
	"telnet",
	"terms",
	"terms_of_use",
	"test",
	"testimonials",
	"theme",
	"themes",
	"today",
	"tools",
	"topic",
	"topics",
	"tour",
	"training",
	"translate",
	"translations",
	"trending",
	"trial",
	"true",
	"umac_128",
	"umac_128_etm",
	"umac_64",
	"umac_64_etm",
	"undefined",
	"unfollow",
	"unsubscribe",
	"update",
	"upgrade",
	"usenet",
	"user",
	"username",
	"users",
	"uucp",
	"var",
	"verify",
	"video",
	"view",
	"void",
	"vote",
	"webmail",
	"webmaster",
	"website",
	"widget",
	"widgets",
	"wiki",
	"wpad",
	"write",
	"www",
	"www1",
	"www2",
	"www3",
	"www4",
	"www_data",
	"you",
	"yourname",
	"yourusername",
	"zlib",
}