function isMobile() {
	var sUserAgent = navigator.userAgent;
	var arr = {
		"iPad": /ipad/i,
		"iPhone OS": /iphone os/i,
		"Midp": /midp/i,
		"UcWeb7": /rv:1.2.3.4/i,
		"UcWeb": /ucweb/i,
		"Android": /android/i,
		"Windows CE": /windows ce/i,
		"Windows Mobile": /windows mobile/i
	};
	for (key in arr) {
		if (sUserAgent.match(arr[key])) {
			return key;
		}
	}
	return '';
}

function appendCssfile(id, file)
{
	var style;
	
	if(id) {
		style = document.getElementById(id);
		if(style) {
			style.src = file;
			return style;
		}
	}

	style = document.createElement('link');
	style.type = 'text/css';
	style.rel = 'stylesheet';
	if(id) style.id = id;
	style.href = file;
	var head = document.getElementsByTagName('head')[0];
	head.appendChild(style);

	return style;
}

function appendCssCode(id, code)
{
	var style;

	function setcode(style, code)
	{
		try{
			//for Chrome Firefox Opera Safari
			style.appendChild(document.createTextNode(code));
		}catch(ex){
			//for IE
			style.styleSheet.cssText = code;
		}
	}
	
	if(id) {
		style = document.getElementById(id);
		if(style) {
			setcode(style, code);
			return style;
		}
	}

	style = document.createElement('style');
	style.type = 'text/css';
	style.rel = 'stylesheet';
	if(id) style.id = id;
	setcode(style, code);
	var head = document.getElementsByTagName('head')[0];
	head.appendChild(style);

	return style;
}

function buildstyles(styles)
{
	var key, code = '';

	for(key in styles) {
		code+= key + ' {';
		for(name in styles[key]) {
			code+= name + ':' + styles[key][name] + ";";
		}
		code+= '}';
	}

	appendCssCode('the-portal-css', code);
}

function removestyles()
{
	var style = document.getElementById('the-portal-css');
	if(!style) return;
	
	if(typeof style.remove == "undefined")
		style.parentNode.removeChild(style);
	else
		style.remove();
}

function buildbgimg(bgcontents)
{
	var a, bg, conf;
	var bgparent = document.querySelector('body > .bg-content');
	var bglist = document.querySelectorAll('body > .bg-content > .bgimg');

	if(!bgparent) return;
	
	for(i = 0; i < bglist.length; i++) {
		bg = bglist[i];
		bg.parentNode.removeChild(bg);
	}

	for(i = 0; i < bgcontents.length; i++) {
		conf = bgcontents[i];
		bg = bglist[i];

		if(conf.href) {
			a = document.createElement('a');
			bg = document.createElement('div');
			a.appendChild(bg);
			a.href = conf.href;
			if(conf.target)
				a.target = "_blank";
		}
		else {
			bg = document.createElement('div');
		}

		if(conf.class)
			bg.className = conf.class;
		if(conf.style) {
			for(key in conf.style) {
				bg.style[key] = conf.style[key];
			}
		}

		if(conf.href)
			bgparent.appendChild(a);
		else
			bgparent.appendChild(bg);
	}
}


function ip2int(ip)
{
    var num = 0;
    ip = ip.split(".");
    num = Number(ip[0]) * 256 * 256 * 256 + Number(ip[1]) * 256 * 256 + Number(ip[2]) * 256 + Number(ip[3]);
    num = num >>> 0;
    return num;
}

function ip6tointX(ip6)
{
  const expandIPv6 = (ip) => {
    let expanded = [];
    let zeroed = false;
    const parts = ip.split(':');
    for (let i = 0; i < 8; ++i) {
      if (i < parts.length) {
        if (parts[i] === '') {
          if (zeroed) {
            throw new Error('Invalid IPv6 address: more than one ::');
          }
          zeroed = true;
          expanded.push(...Array(8 - parts.length + 1).fill('0000'));
        } else {
          expanded.push(parts[i].padStart(4, '0'));
        }
      } else if (!zeroed) {
        expanded.push('0000');
      }
    }
    if (expanded.length !== 8) {
      throw new Error('Invalid IPv6 address: cannot expand');
    }
    return expanded;
  };

  const toBigInt = (expanded) => {
    let high = BigInt(0);
    let low = BigInt(0);
    for (let i = 0; i < 8; ++i) {
      const partBigInt = BigInt(`0x${expanded[i]}`);
      if (i < 4) {
        high = (high << 64n) + partBigInt;
      } else {
        low = (low << 64n) + partBigInt;
      }
    }
    return [high, low];
  };

  try {
    const expanded = expandIPv6(ip6);
    const [high, low] = toBigInt(expanded);
    return [high, low];
  } catch (error) {
    throw new Error(`Cannot convert IPv6 address to BigInt: ${error.message}`);
  }
}

function ip6toint(ip6)
{
  let parts = ip6.split(':');

  if (parts.includes('')) {
    let zeros = 8 - parts.length;
    let emptyIndex = parts.indexOf('');

    if (parts.filter(p => p === '').length > 1) {
      throw new Error('Invalid IPv6 address: more than one ::');
    }

    if (emptyIndex !== 0 && emptyIndex !== parts.length - 1) {
      parts = parts.slice(0, emptyIndex).concat(Array(zeros + 1).fill('0000'), parts.slice(emptyIndex + 1));
    } else {
      parts = parts.concat(Array(zeros).fill('0000'));
    }
  }

  for (let part of parts) {
    if (/^[0-9a-fA-F]{0,4}$/.test(part)) {
      part = part.padStart(4, '0');
    } else if (part.length > 4) {
      throw new Error('Invalid IPv6 address: segment longer than 16 bits');
    }
  }

  let high = BigInt(0);
  let low = BigInt(0);
  for (let i = 0; i < 8; i++) {
    let value = BigInt(`0x${parts[i]}`);
    if (i < 4) {
      high = (high << 64n) + value;
    } else {
      low = (low << 64n) + value;
    }
  }

  return [high, low];
}

function int2ip(num)
{
    var str;
    var tt = new Array();
    tt[0] = (num >>> 24) >>> 0;
    tt[1] = ((num << 8) >>> 24) >>> 0;
    tt[2] = (num << 16) >>> 24;
    tt[3] = (num << 24) >>> 24;
    str = String(tt[0]) + "." + String(tt[1]) + "." + String(tt[2]) + "." + String(tt[3]);
    return str;
}

function int2Ip6(highBits, lowBits, simplify = true)
{
	const toHex = (value) => simplify ? value.toString(16) : value.toString(16).padStart(4, '0');
	const segments = [];

	for (let i = 7; i >= 0; i--) {
		let segmentValue;
		if (i >= 4) {
			segmentValue = (highBits >> BigInt(64 * (i - 4))) & BigInt('0xffffffffffffffff');
		} else {
			segmentValue = (lowBits >> BigInt(64 * (i))) & BigInt('0xffffffffffffffff');
		}
		segments.push(toHex(segmentValue));
	}

	let compressed = [];
	let consecutiveZeros = 0;
	for (let segment of segments) {
		if (segment === '0000' || segment === '0') {
		  consecutiveZeros++;
		} else {
		  if (consecutiveZeros > 0) {
			if (compressed.length === 0 || compressed[compressed.length - 1] !== '') {
			  compressed.push('');
			}
			consecutiveZeros = 0;
		  }
		  compressed.push(segment);
		}
	}

	if (consecutiveZeros > 0 && compressed[compressed.length - 1] !== '') {
		compressed.push('');
	}

	return compressed.join(':');
}

function strToInt(str)
{
	var number = parseInt($.trim(str), 10);
	
	if(isNaN(number)) number = 0;
	
	return number;
}

function set_location_href(url)
{
	if(typeof location.href == 'string')
		location.href = url;
	else
		windown.location.href = url;
}

function get_location_href()
{
	if(typeof location.href == 'string')
		return location.href;
	else
		return windown.location.href;
}

function get_location_urlpath()
{
	return get_location_href().split('?')[0];
}

function build_url_param(param)
{
	var txt = '';

	if(typeof param == 'object') {
		arg = [];
		for(key in param) {
			arg.push(key + '=' + encodeURIComponent(param['key']));
		}
		return arg.join('&');
	}

	return param;
}

function get_random_str(len)
{
    var map = 'abacdefghjklmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789',
		i, index, max = map.length, str = '';
    len = len || 15;
    for (i = 0; i < len; i++) {
		index = Math.floor(Math.random() * (max + 1)) % max;
		str += map[index];
    }
    return str;
}

$.storage = function() {
	var s;
	if(localStorage) {
		s = {
		  get: function (key) {
			var expired, e;
			if(key == "key") key = "skey";
			e = localStorage.getItem(key);
			if(e === null) return undefined;
			var curtm = (new Date).getTime();
			var v = e.match(new RegExp("([^;]*)(;|$)"));
			if(v) {
				if(v[2]) {
					expired = parseInt(v[2], 10);
					if(!isNaN(expired) && expired
					&& expired < curtm) {
						localStorage.removeItem(key);
						return undefined;
					}
				}
				return v[1];
			}
			return undefined;
		  },
		  set: function (key, val, day) {
			var r, expired;
			if(key == "key") key = "skey";
			if(day > 0) {
				r = new Date;
				expired = r.setTime(r.getTime() + 36e5 * day);
			}
			return localStorage.setItem(key, val + ';' + expired);
		  },
		  del: function (key) {
			localStorage.removeItem(key);
		  },
		  cleanexpired: function () {
			var i, key, val, e, list = window.localStorage;
			var expired, curtm = (new Date).getTime();
			if(key == "key") key = "skey";
			for(i = list.length - 1; i >= 0; i--){
				key = list.key(i);
				val = list.getItem(key);
				if(val === null) continue;
				e = val.match(new RegExp("([^;]*)(;|$)"));
				if(e && e[2]) {
					expired = parseInt(e[2], 10);
					if(!isNaN(expired) && expired
					&& expired < curtm) {
						localStorage.removeItem(key);
					}
				}
			}
		  }
		}
	}
	else {
		s = { get: function (key) {
				var e = document.cookie.match(new RegExp("(^| )" + key + "=([^;]*)(;|$)"));
				return e ? decodeURIComponent(e[2]) : "";
			}, getOrigin: function (key) {
				var e = document.cookie.match(new RegExp("(^| )" + key + "=([^;]*)(;|$)"));
				return e ? e[2] : "";
			}, set: function (key, val, day, domain, path) {
				var r = new Date;
				day ? (r.setTime(r.getTime() + 36e5 * day), document.cookie = key + "=" + val + "; expires=" + r.toGMTString() + "; path=" + (path ? path : "/") + "; " + (domain ? "domain=" + domain + ";" : "")) : document.cookie = key + "=" + val + "; path=" + (path ? path : "/") + "; " + (domain ? "domain=" + domain + ";" : "");
			}, del: function (key, domain, path) {
				document.cookie = key + "=; expires=Mon, 26 Jul 1997 05:00:00 GMT; path=" + (path ? path : "/") + "; " + (domain ? "domain=" + domain + ";" : "");
			}, uin: function () {
				var key = $.cookie.get("uin");
				return key ? parseInt(key.substring(1, key.length), 10) : null;
			}, cleanexpired: function () {
			}
		}
	}
	s.cleanexpired();
	return s;
}();

function ShowWindow(url, args, width, height)
{
	var left = (window.screen.width - width) / 2;
	var top  = (window.screen.height - height) / 2 - 50;

	if (args == "")
		args = "scrollbars=1,toolbar=0,menubar=0,status=0,location=0";
	else
		args += ",location=0";

	args += ",top=" + top + ",left=" + left + ",height=" + height + ",width=" + width;
	return window.open(url, "_blank", args);
}

function raasportal() {
	var url = window.location.search;
	var intr = 0;
	var url_302;
	var url_str;
	var url_pram = {};
	var pageurl = url.split('&iarmdst=');
	if (pageurl.length == 2 && pageurl[1] != "") {
		url_302 = decodeURIComponent(pageurl[1]);
		if (url_302.indexOf('http') != 0) url_302 = 'http://' + url_302;
	} else {
		url_302 = "";
	}
	var clienturl = pageurl[0].split('?');
	if (clienturl.length == 2 && clienturl[1] != "") {
		url_str = clienturl[1];
		var param = url_str.split('&');
		var p, i;
		for (i = 0; i < param.length; i++) {
			p = param[i].split('=');
			if (p.length == 2) {
				try {
					url_pram[p[0]] = decodeURIComponent(p[1]);
				}
				catch(err) {
					url_pram[p[0]] = '';
				}
			}
		}
		if(!url_pram.bras && url_pram.nasip) url_pram.bras = url_pram.nasip;
		if(!url_pram.clientip && url_pram.wlanuserip && url_pram.wlanuserip == int2ip(ip2int(url_pram.wlanuserip))) url_pram.clientip = url_pram.wlanuserip;
		var url_PX = [];
		for(key in url_pram) {
			url_PX.push(key + '=' + url_pram[key]);
		}
		url_str = '?' + url_PX.join('&');
	}
	else {
		url_str = "";
	}

	if (url_302) {
		if(url_302.indexOf('captive.apple.com') != -1
		|| url_302.indexOf('www.gstatic.com/generate_204') != -1)
			url_302 = '';
	}

	window.raas_portal_url_pram = url_pram;
	window.raas_portal_url_302 = url_302;

	function build_url_param()
	{
		var args = [];

		for(key in window.raas_portal_url_pram) {
			args.push(key + '=' + window.raas_portal_url_pram[key]);
		}
		url_str = '?' + args.join('&');
	}

	/*
	 * 功能: 获取短信验证码
	 * user: 账号
	 */
	function getsmscode(data) {
		var success;
		var opt = {};
		for (var key in data)
			opt[key] = data[key];

		success = opt.success || function(d) {};
		opt.url = 'api/getcode.php';

		if (intr) {
			clearInterval(intr);
			intr = 0;
		}

		opt.dataType = opt.dataType || 'json';
		return $.post(opt);
	}

	function getacct(data) {
		var success;
		var opt = {};
		for (var key in data)
			opt[key] = data[key];

		success = opt.success || function(d) {};
		opt.url = 'api/getacct.php' + url_str;

		if (intr) {
			clearInterval(intr);
			intr = 0;
		}

		opt.dataType = opt.dataType || 'json';
		return $.post(opt);
	}

	function setacct(data) {
		var success;
		var opt = {};
		for (var key in data)
			opt[key] = data[key];

		success = opt.success || function(d) {};
		opt.url = 'api/setacct.php' + url_str;
		opt.success = function(d) {
			switch(d.ret) {
				case -1:
					d.msg = '参数不正确！' + d.msg;
				break;
				case 2:
					d.msg = '域名不存在！';
				break;
				case 3:
				case 4:
					d.msg = '帐号或密码不正确！[' + d.ret + ']';
				break;
				case 5:
					d.msg = '运营商配置不存在！';
				break;
				case 6:
					d.msg = '无效的运营商帐号！';
				break;
				case 7:
					d.msg = '保存配置失败！';
				break;
				default:
				break;
			}
			success.call(opt, d);
		};

		if (intr) {
			clearInterval(intr);
			intr = 0;
		}
		opt.dataType = opt.dataType || 'json';
		return $.post(opt);
	}

	function login(data) {
		var success;
		var opt = {};
		for (var key in data)
			opt[key] = data[key];

		success = opt.success || function(d) {};
		opt.url = 'api/login.php' + url_str;
		opt.success = function(d) {
			if (d.ret == 0) {
				if (!d.succ_url)
					d.succ_url = url_302;
				aff_ack_auth(opt.data);
			}
			switch(d.ret) {
				case 121:
				case 122:
				case 3:
					d.ret = 0;
				break;
				default:
				break;
			}
			success.call(opt, d);
		}

		if (intr) {
			clearInterval(intr);
			intr = 0;
		}
		opt.dataType = opt.dataType || 'json';
		return $.post(opt);
	}

	function logoff(data) {
		var opt = {};

		if (intr)
			clearInterval(intr);

		for (var key in data)
			opt[key] = data[key];

		opt.url = 'api/logoff.php' + url_str;
		
		opt.dataType = opt.dataType || 'json';
		return $.post(opt);
	}

	function aff_ack_auth(data) {
		// AFF_ACK_AUTH
		return $.post({
			url: 'api/ack_auth.php' + url_str,
			data: data,
			dataType: 'json'
		});
	}

	function stat(data) {
		var success, error;
		var opt = {};

		if (intr)
			clearInterval(intr);

		for (var key in data)
			opt[key] = data[key];

		opt.dataType = opt.dataType || 'json';
		opt.timeout = opt.timeout || 10;
		opt.status = opt.status || function(d, timeout) {};
		success = opt.success || function(d) {};
		error = opt.error || function() {
			clearInterval(intr);
			intr = 0;
		};
		opt.url = 'api/stat.php' + url_str;

		opt.success = function(d) {
			if (d.ret)
				opt.status.call(opt, d, opt.timeout);
			if (opt.timeout-- && (d.ret == 2 || d.ret == 3 || d.ret == 4)) {
				if (d.ret == 4)
					aff_ack_auth(opt.data);
				return;
			}

			clearInterval(intr);
			intr = 0;
			d.timeout = opt.timeout <= 0;
			success.call(opt, d);
		}
		opt.error = function(jqXHR, textStatus, errorThrown) {
			if (opt.timeout--) {
				opt.status.call(opt, {}, opt.timeout);
				return;
			}
			clearInterval(intr);
			intr = 0;
			error.call(jqXHR, textStatus, errorThrown);
		}

		intr = setInterval(function() {
			$.post(opt);
		}, 1000);
		
		$.post(opt);

		return intr;
	}

	function route(app, rules, error)
	{
		var i, j, r, cip, longip, dip, found, tp, pathname, status = {};
		var error = error || function() {};

		if(url_pram.clientip)
			cip = url_pram.clientip;
		else
			cip = '';

		$.post({
			url: 'api/ip.php' + (url_302?'?iarmdst=' + url_302:''),
			data: url_pram,
			async: false,
			dataType: 'json',
			success: function(res) {
				if(res.ret) {
					if(res.ret == 302) {
						set_location_href(res.data);
					}
					return;
				}
				if(!cip) cip = res.data.ip;
				for(key in res.data)
					status[key] = res.data[key];
			},
			error: function(d) {
				if(d.status == 500 && url_pram.ticket) {
					var service = url_str.replace((url_str.indexOf('?')>-1?'?':'&') + 'ticket='+url_pram.ticket, '');
					service = get_location_urlpath() + service + (url_302?(service?'&':'?') + 'iarmdst=' + encodeURIComponent(url_302):'');
					set_location_href(service);
				}
				return;
			}
		});

		if(cip) {
			longip = ip2int(cip);
		} else
			longip = 0;

		for(i in rules) {
			r = rules[i];

			if(!r.match.ip || r.match.ip.indexOf(cip) == -1) {
				found = 0;
				if(r.match.iprange && r.match.iprange.length) {
					if(r.match.islongip) {
						for(j = 0; j < r.match.iprange.length; j++) {
							dip = r.match.iprange[j];
							if (longip >= dip.sip
							 && longip <= dip.eip) {
								found = 1;
								break;
							}
						}
					}
					else {
						for(j = 0; j < r.match.iprange.length; j++) {
							dip = r.match.iprange[j];
							if(dip.ipv6 && typeof(dip.ipv6) == 'string')
								dip.ipv6 = parseInt(dip.ipv6);
							else
								dip.ipv6 = 0;

							if(dip.ipv6) {
								if (cip >= dip.sip
								 && cip <= dip.eip) {
									found = 1;
									break;
								}
							}
							else {
								if (longip >= ip2int(dip.sip)
								 && longip <= ip2int(dip.eip)) {
									found = 1;
									break;
								}
							}
						}
					}
				}

				if(found == 0
				&&((r.match.ip && r.match.ip.length)
				 ||(r.match.iprange && r.match.iprange.length)))
					continue;
			}
			
			if(r.vlan && r.vlan != url_pram.vlan)
				continue;
			
			if(r.domain && r.domain != url_pram.domain)
				continue;
			
			if(window.location.pathname)
				pathname = window.location.pathname;
			else
				pathname = get_location_href().split('?')[0].replace(window.location.origin,'');

			pathname = 'tp/' + r.tp + pathname;

			if(r.type == "url") {
				if(url_str)
					set_location_href(pathname + url_str + '&_tp_=' + i + (url_302?'&iarmdst=' + url_302:''));
				else
					set_location_href(pathname + '?_tp_=' + i + (url_302?'&iarmdst=' + url_302:''));
			}
			else {
				if(r.title)
					document.title = r.title;

				var link;
				if((link = document.querySelector('head > link')))
					link.parentNode.removeChild(link);
				appendCssfile('the-stylefile', '/tp/' + r.tp + '/css/index.css');

				if(r.conf) {
					if(r.conf.disvlan) {
						url_pram.vlan = '0.0';
						url_str = url_str.replace(/vlan=[\d.]+&?/g, '');
					}

					if(r.conf.theme)
						$('body').addClass(r.conf.theme);

					if(r.conf.stylesheet) {
						if(r.conf.stylesheet.global)
							buildstyles(r.conf.stylesheet.global);

						if(r.conf.stylesheet.stylefile)
							appendCssfile('the-' + r.tp + '-stylefile', 'tp-data/' + r.tp + '/css/' + r.conf.stylefile);

						if(r.conf.stylesheet.bgcontent)
							buildbgimg(r.conf.stylesheet.bgcontent);
					}
				}

				$.get({
					url: pathname,
					udata: r,
					dataType: 'text',
					success: function(data) {
						r.clientip = cip;
						r.status = status;
						r.page = $(data);
						app.data('route', r);

						var script = document.createElement('script');
						script.type = 'text/javascript';
						script.src = 'tp/' + r.tp + '/js/index.js';

						script.onload =
						document.getElementsByTagName('head')[0].appendChild(script);
					},
					error: error
				});
			}
			return;
		}

		error.call(0, 0);
	}

	if(isMobile()) {
		$('meta[name="viewport"]').attr('content', 'width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0, user-scalable=no');
		$('body').addClass('mobile');
	}
	else
		$('body').addClass('pc');

	return {
		build_url_param: build_url_param,
		getacct: getacct,
		setacct: setacct,
		login: login,
		stat: stat,
		logoff: logoff,
		route: route,
		getsmscode: getsmscode
	};
}
