/*
 * Copyright (C) 677
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <wand/magick-wand.h>
#include <ngx_md5.h>

#define MAXCHAR 64
#define MAXCAPTCHA 8192
#define MAXWIDTH 512
#define MAXHEIGHT 512
#define HASHLEN 16 // 0 - 32

typedef struct {
	ngx_uint_t   maxCaptcha;
	ngx_uint_t   width;
	ngx_uint_t   height;
	ngx_uint_t   charCount;
	ngx_int_t   charSpacing;
	ngx_uint_t   fontSize;
	ngx_str_t	 font;
	char		*font_cstr;
	ngx_str_t	 cookieHashName;
	ngx_str_t	 cookieSaltName;
	ngx_str_t	 cookieSecret;
	unsigned char** image_templates;
	size_t*		 image_sizes;
	char*		 image_chars;
    ngx_flag_t	 enable;
} ngx_http_captcha_loc_conf_t;

static char* ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_captcha_init(ngx_http_captcha_loc_conf_t *cf);
static void* ngx_http_captcha_template(ngx_http_captcha_loc_conf_t *cplcf, 
		size_t* image_length_ptr, char * image_chars,
		MagickWand *wand, PixelWand *bg_wand, PixelWand *fg_wand, DrawingWand *dwand);

static void* ngx_http_captcha_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char * ngx_set_char_spacing(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_captcha_commands[] = {
	{ ngx_string("captcha"),
		NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
		ngx_http_captcha_conf,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, maxCaptcha),
		NULL },

	{ ngx_string("captcha_char_count"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, charCount),
		NULL },

	{ ngx_string("captcha_width"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, width),
		NULL },

	{ ngx_string("captcha_height"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, height),
		NULL },

	{ ngx_string("captcha_char_count"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, charCount),
		NULL },

	{ ngx_string("captcha_char_spacing"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_set_char_spacing,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, charSpacing),
		NULL },

	{ ngx_string("captcha_font_size"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, fontSize),
		NULL },

	{ ngx_string("captcha_font"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, font),
		NULL },

	{ ngx_string("captcha_cookie_hash_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, cookieHashName),
		NULL },

	{ ngx_string("captcha_cookie_salt_name"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, cookieSaltName),
		NULL },

	{ ngx_string("captcha_cookie_secret"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_captcha_loc_conf_t, cookieSecret),
		NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_captcha_module_ctx = {
	NULL,							/* preconfiguration */
	NULL,							/* postconfiguration */

	NULL,                          /* create main configuration */
	NULL,                          /* init main configuration */

	NULL,                          /* create server configuration */
	NULL,                          /* merge server configuration */

	ngx_http_captcha_create_loc_conf,  /* create location configuration */
	ngx_http_captcha_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_http_captcha_module = {
	NGX_MODULE_V1,
	&ngx_http_captcha_module_ctx, /* module context */
	ngx_http_captcha_commands,   /* module directives */
	NGX_HTTP_MODULE,               /* module type */
	NULL,                          /* init master */
	NULL,                          /* init module */
	NULL,                          /* init process */
	NULL,                          /* init thread */
	NULL,                          /* exit thread */
	NULL,                          /* exit process */
	NULL,                          /* exit master */
	NGX_MODULE_V1_PADDING
};

static const u_int MaxPixel = 100;
static const u_int MaxRotate = 8;
static const char *cChars = "ABDEFGHJKLMNPQRSTUVWXYZabdeghijkmnpqrstuvwxyz23456789";
static const char* bgColor = "#ffffff";
static const char* fgColor = "#2d2d2d";
static u_int nChars;
static u_int lineCount = 3;
static int rotate;
static char ch[MAXCHAR];

static void md5_make_digest(char *md5str, const unsigned char *digest, int len) {
	static const char hexits[17] = "0123456789abcdef";
	int i;

	for (i = 0; i < len; i++) {
		md5str[i * 2]       = hexits[digest[i] >> 4];
		md5str[(i * 2) + 1] = hexits[digest[i] &  0x0F];
	}
}

static char *
ngx_set_char_spacing(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_captcha_loc_conf_t  *cplcf = conf;

    ngx_str_t        *value;
    ngx_uint_t        n, minus;

    if (cplcf->charSpacing != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].data[0] == '-') {
        n = 1;
        minus = 1;

    } else {
        n = 0;
        minus = 0;
    }

    cplcf->charSpacing = ngx_atoi(&value[1].data[n], value[1].len - n);
    if (cplcf->charSpacing == NGX_ERROR) {
        return "invalid number";
    }

    if (minus) {
        cplcf->charSpacing = -cplcf->charSpacing;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_captcha_handler(ngx_http_request_t *r)
{
	ngx_int_t     rc;
	ngx_buf_t    *b;
	ngx_chain_t   out;
	unsigned char *image;

	ngx_http_captcha_loc_conf_t  *cplcf;
	cplcf = ngx_http_get_module_loc_conf(r, ngx_http_captcha_module);

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK && rc != NGX_AGAIN) {
		return rc;
	}

	r->headers_out.content_type.len = sizeof("image/jpeg") - 1;
	r->headers_out.content_type.data = (u_char *) "image/jpeg";

	int captcha_index = ngx_random() % cplcf->maxCaptcha;

	ngx_md5_t md5;
	u_char  hash[16];
	char	hash_hex[HASHLEN];
	u_char  salt_buf[32];
	size_t	salt_buf_len;

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, cplcf->cookieSecret.data, cplcf->cookieSecret.len);
	ngx_md5_update(&md5, (char*)&cplcf->image_chars[captcha_index * cplcf->charCount], cplcf->charCount);
	/*cplcf->image_chars[captcha_index * cplcf->charCount + 4] = '\0';*/
	/*printf((char*)&cplcf->image_chars[captcha_index * cplcf->charCount]);*/
	/*printf("\n");*/
	salt_buf_len = ngx_sprintf(salt_buf, "%d", ngx_random()) - salt_buf;
	ngx_md5_update(&md5, salt_buf, salt_buf_len);
	ngx_md5_final(hash, &md5);
	md5_make_digest(hash_hex, hash, HASHLEN / 2);

	ngx_table_elt_t  *set_cookie_hash = ngx_list_push(&r->headers_out.headers);
	ngx_table_elt_t  *set_cookie_salt = ngx_list_push(&r->headers_out.headers);
	if (set_cookie_hash == NULL || set_cookie_salt == NULL) {
		return NGX_ERROR;
	}

	// set_cookie_hash
	{
		set_cookie_hash->hash = 1;
		ngx_str_set(&set_cookie_hash->key, "Set-Cookie");
		int cookie_buf_len = cplcf->cookieHashName.len + HASHLEN + 1;
		set_cookie_hash->value.data = ngx_palloc(r->pool, cookie_buf_len);
		if (set_cookie_hash->value.data == NULL) {
			return NGX_ERROR;
		}
		/*ngx_sprintf(set_cookie_hash->value.data, "%s=%s", ...);*/
		unsigned char *p = set_cookie_hash->value.data;
		p = ngx_cpymem(p, cplcf->cookieHashName.data, cplcf->cookieHashName.len);
		*p++ = '=';
		p = ngx_cpymem(p, hash_hex, HASHLEN);
		set_cookie_hash->value.len = cookie_buf_len;
	}
	// set_cookie_salt
	{
		set_cookie_salt->hash = 1;
		ngx_str_set(&set_cookie_salt->key, "Set-Cookie");
		int cookie_buf_len = cplcf->cookieSaltName.len + salt_buf_len + 1;
		set_cookie_salt->value.data = ngx_palloc(r->pool, cookie_buf_len);
		if (set_cookie_salt->value.data == NULL) {
			return NGX_ERROR;
		}
		/*ngx_sprintf(set_cookie_salt->value.data, "%s=%s", ...);*/
		unsigned char *p = set_cookie_salt->value.data;
		p = ngx_cpymem(p, cplcf->cookieSaltName.data, cplcf->cookieSaltName.len);
		*p++ = '=';
		p = ngx_cpymem(p, salt_buf, salt_buf_len);
		set_cookie_salt->value.len = cookie_buf_len;
	}

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = cplcf->image_sizes[captcha_index];

	if (r->method == NGX_HTTP_HEAD) {
		rc = ngx_http_send_header(r);

		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}
	}

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	out.buf = b;
	out.next = NULL;

	image = ngx_palloc(r->pool, cplcf->image_sizes[captcha_index]);
	if (image == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for image image.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_memcpy(image, cplcf->image_templates[captcha_index], cplcf->image_sizes[captcha_index]);

	b->pos = image;
	b->last = image + cplcf->image_sizes[captcha_index];

	b->memory = 1;
	b->last_buf = 1;

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_captcha_init(ngx_http_captcha_loc_conf_t *cplcf)
{
	printf("captcha init begin.\n");

	u_int i;
	MagickWand *wand;
	PixelWand *bg_wand, *fg_wand;
	DrawingWand *dwand;

	nChars = strlen(cChars);

	MagickWandGenesis();
	wand = NewMagickWand();
	bg_wand = NewPixelWand();
	fg_wand = NewPixelWand();
	dwand = NewDrawingWand();

	PixelSetColor(bg_wand, bgColor);
	PixelSetColor(fg_wand, fgColor);	

	if ((cplcf->image_templates = malloc(cplcf->maxCaptcha * sizeof(unsigned char*))) == NULL ||
			(cplcf->image_sizes = malloc(cplcf->maxCaptcha * sizeof(size_t))) == NULL ||
			(cplcf->image_chars = malloc(cplcf->maxCaptcha * sizeof(unsigned char) * cplcf->charCount)) == NULL) {
		perror("malloc()");
		return NGX_ERROR;
	}
	for (i = 0; i < cplcf->maxCaptcha; i++) {
		cplcf->image_templates[i] = ngx_http_captcha_template(cplcf, 
				&cplcf->image_sizes[i], &cplcf->image_chars[i * cplcf->charCount],
				wand, bg_wand, fg_wand, dwand);
	}

	DestroyMagickWand(wand);
	DestroyPixelWand(fg_wand);
	DestroyPixelWand(bg_wand);
	DestroyDrawingWand(dwand);
	MagickWandTerminus();

	printf("captcha init end.\n");
	return i;
}

static void* ngx_http_captcha_template(ngx_http_captcha_loc_conf_t *cplcf,
		size_t* image_length_ptr, char* image_chars,
		MagickWand *wand, PixelWand *bg_wand, PixelWand *fg_wand, DrawingWand *dwand)
{
	u_int i, x, y, idx;

	ClearDrawingWand(dwand);
	MagickNewImage(wand, cplcf->width, cplcf->height, bg_wand);

	DrawSetFillColor(dwand, fg_wand);
	DrawSetTextEncoding(dwand, "UTF8");
	MagickBooleanType b = DrawSetFont(dwand, cplcf->font_cstr);
	if (b == MagickFalse) {
		printf("Font load error.\n");
		return 0;
	}
	DrawSetFontSize(dwand, cplcf->fontSize);

	u_int char_count = cplcf->charCount << 1;
	for (i = 0; i < char_count; i++) {
		idx = ngx_random() % nChars;
		ch[i] = *(cChars + idx);
		*image_chars++ = ngx_tolower(ch[i]);
		ch[++i] = ' ';
	}
	if (i > 0) {
		ch[--i] = '\0';
	}
	rotate = ngx_random() % MaxRotate;
	if (rotate & 1) {
		rotate = -rotate;
		y = cplcf->height - 5; 
	} else {
		y = cplcf->fontSize - 5;
	}
	DrawRotate(dwand, rotate);
	DrawSetTextInterwordSpacing(dwand, cplcf->charSpacing);
	DrawAnnotation(dwand, 5, y, (const unsigned char*)ch);

	for (i = 0; i < MaxPixel; i++) {
		x = ngx_random() % cplcf->width;
		y = ngx_random() % cplcf->height;
		DrawPoint(dwand, x, y);
		if (x & 1) {
			DrawPoint(dwand, x, ++y);
			DrawPoint(dwand, --x, ++y);
		} else {
			DrawPoint(dwand, ++x, ++y);
			DrawPoint(dwand, ++x, ++y);
		}
		if (i < lineCount) {
			DrawLine(dwand, x, y, (cplcf->width - y), (cplcf->height - x));
		}
	}

	MagickDrawImage(wand, dwand);
	MagickSetImageFormat(wand, "jpeg");

	unsigned char *image = MagickGetImageBlob(wand, image_length_ptr);

	MagickRemoveImage(wand);

	return image;
}

static void *
ngx_http_captcha_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_captcha_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_captcha_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->maxCaptcha = NGX_CONF_UNSET_UINT;
	conf->width = NGX_CONF_UNSET_UINT;
	conf->height = NGX_CONF_UNSET_UINT;
	conf->charCount = NGX_CONF_UNSET_UINT;
	conf->charSpacing = NGX_CONF_UNSET;
	conf->fontSize = NGX_CONF_UNSET_UINT;
	conf->font.data = NULL;
	conf->font.len = 0;
	conf->cookieHashName.data = NULL;
	conf->cookieHashName.len = 0;
	conf->cookieSaltName.data = NULL;
	conf->cookieSaltName.len = 0;
	conf->cookieSecret.data = NULL;
	conf->cookieSecret.len = 0;
    conf->enable = NGX_CONF_UNSET;
	return conf;
}

static char *
ngx_http_captcha_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_captcha_loc_conf_t *prev = parent;
	ngx_http_captcha_loc_conf_t *conf = child;

	ngx_conf_merge_uint_value(conf->maxCaptcha, prev->maxCaptcha, 100);
	ngx_conf_merge_uint_value(conf->width, prev->width, 120);
	ngx_conf_merge_uint_value(conf->height, prev->height, 45);
	ngx_conf_merge_uint_value(conf->charCount, prev->charCount, 4);
	ngx_conf_merge_value(conf->charSpacing, prev->charSpacing, -4);
	ngx_conf_merge_uint_value(conf->fontSize, prev->fontSize, 36);
	ngx_conf_merge_str_value(conf->font, prev->font, "simsun");
	ngx_conf_merge_str_value(conf->cookieHashName, prev->cookieHashName, "captcha_h");
	ngx_conf_merge_str_value(conf->cookieSaltName, prev->cookieSaltName, "captcha_s");
	ngx_conf_merge_str_value(conf->cookieSecret, prev->cookieSecret, "yoursecret");
    ngx_conf_merge_value(conf->enable, prev->enable, 0);

	if (conf->maxCaptcha < 1 || conf->maxCaptcha > MAXCAPTCHA) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "max_captcha must be large than 0 and less than %d", MAXCAPTCHA);
		return NGX_CONF_ERROR;
	}
	if (conf->width > MAXWIDTH) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "width must be less than %d", MAXWIDTH);
		return NGX_CONF_ERROR;
	}
	if (conf->height > MAXHEIGHT) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "height must be less than %d", MAXHEIGHT);
		return NGX_CONF_ERROR;
	}
	if (conf->fontSize > conf->height) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "font_size is too large");
		return NGX_CONF_ERROR;
	}
	if (conf->cookieHashName.len == 0 || conf->cookieSaltName.len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cookie name cannot be empty");
		return NGX_CONF_ERROR;
	}
	if (conf->cookieSecret.len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cookie secret cannot be empty");
		return NGX_CONF_ERROR;
	}

    if(conf->enable) {
		conf->font_cstr = ngx_pcalloc(cf->pool, conf->font.len + 1);
		ngx_memcpy(conf->font_cstr, conf->font.data, conf->font.len);
		conf->font_cstr[conf->font.len] = '\0';
		if (conf->charCount > (MAXCHAR >> 1)) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "char_count must be less than %d", MAXCHAR >> 1);
			return NGX_CONF_ERROR;
		}
		ngx_http_captcha_init(conf);
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_captcha_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t  *clcf;
	ngx_http_captcha_loc_conf_t *cplcf = conf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_captcha_handler;

    ngx_conf_set_num_slot(cf, cmd, conf);

    cplcf->enable = 1;

	return NGX_CONF_OK;
}
