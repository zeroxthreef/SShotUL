#include <kore/kore.h>
#include <kore/http.h>

#include <ctype.h>


#include "snowflake.h"


#define URL "https://ssul.vertesine.com"

typedef struct
{
  char *mime;
  char *extension;
} mime_t;

mime_t mimes[] = { /* this is taken from my in progress vertesine backend code */
  {"text/plain", "txt"},
  {"text/html", "html"},
  {"text/html", "htm"},
  {"text/css", "css"},
  {"text/javascript", "js"},
  {"image/gif", "gif"},
  {"image/png", "png"},
  {"image/jpeg", "jpg"},
  {"image/bmp", "bmp"},
  {"image/webp", "webp"},
  {"audio/midi", "mid"},
  {"audio/mpeg", "mpg"},
  {"audio/webm", "webm"},
  {"audio/mpeg", "mp3"},
  {"audio/wav", "wav"},
  {"video/webm", "webm"},
  {"video/ogg", "ogg"},
  {"video/mp4", "mp4"},
  {"video/avi", "avi"},
  {"application/zip", "zip"},
  {"font/ttf", "ttf"},
  {"application/octet-stream/exe", "exe"},
  {"application/octet-stream/c", "c"},
  {"application/octet-stream/h", "h"},
  {"application/octet-stream", ""}
};

const char *reply = "<html><meta name=\"description\" content=\"Terrible screenshot/file uploading service\"><meta name=\"DC.title\" content=\"SSUL File Uploading Thing\"><title>SShotUL</title><center><h1>Screen Shot Uploader</h1><br><center>This is only for me lol. If you want the auth key, email me at zeroxthreef@gmail.com</center></center><br><br><marquee>you can find this on github at <a href=\"https://github.com/zeroxthreef/SShotUL\">this link</a></marquee></html>";

int	home(struct http_request *);

int	upload(struct http_request *);

int	imgsearch(struct http_request *);

/* functions */

uint8_t *ReadFile(char *location, unsigned long *sizePtr) /* from my vertesine backend again */
{
  FILE *f;
  unsigned long size;
  uint8_t *dataPtr;
  f = fopen(location, "rb");
  if(f == NULL){
    //printf("Error cant find\n");
    return (uint8_t *)NULL;
  }

  fseek(f,0,SEEK_END);
  size = ftell(f);
  rewind(f);

  dataPtr = (uint8_t *)kore_malloc(size + 1);

  fread(dataPtr, sizeof(unsigned char), size, f);

  if(dataPtr == NULL){
    kore_log(LOG_CRIT, "Could not allocate memory");
    return (uint8_t *)NULL;
  }

  fclose(f);

  *sizePtr = size;
  return dataPtr;
}

short DetectMime(struct http_request *req, char *filename) /* another quick thing taken from my vertesine backend */
{
  unsigned long i;
  char *extension = strrchr(filename, '.');


  if(extension == NULL)
  {
    return 1;
  }
  extension++;
  if(extension == NULL)
  {
    return 1;
  }

  for(i = 0; i < sizeof(mimes) / sizeof(mimes[0]); i++)
  {
    if(strcmp(extension, mimes[i].extension) == 0)
    {
			http_response_header(req, "content-type", mimes[i].mime);
			return 0;
    }
  }


  http_response_header(req, "content-type", mimes[sizeof(mimes[0]) / sizeof(mimes)].mime);
	return 2;
}

static void AddHeaders(struct http_request *req)
{
	http_response_header(req, "Content-Language", "en-US");
	/* http_response_header(req, "Accept-Ranges", "bytes"); */ /* TODO make a range parser */
	http_response_header(req, "Server", "SSUL");
}

/* serve things */

int sshotul_load(int state)
{
	if(state != KORE_MODULE_UNLOAD)
	{
		kore_log(LOG_NOTICE, "initializing sshotul");
		snowflake_init(0, 0);
	}


	return KORE_RESULT_OK;
}

int home(struct http_request *req)
{
	AddHeaders(req);
	http_response_header(req, "Content-Type", "text/html"); /* for the page */
	http_response(req, 200, reply, strlen(reply));
	return KORE_RESULT_OK;
}

int upload(struct http_request *req)
{
	unsigned char data[1024];
	struct http_file *file;
	long int ID = 0;
	char *IDstr = NULL;
	char *authorization = NULL;
	char *key = NULL;
	char *redir = NULL;
	FILE *filew;
	size_t r;
	size_t size = 0;
	short doMinus1 = 0;



	AddHeaders(req);

	key = ReadFile("key.txt", &size);

	if(key[strlen(key)] == '\n')
		doMinus1++;


	http_request_header(req, "authorization", &authorization);


	if(req->method == HTTP_METHOD_POST)
	{
		if(authorization == NULL)
		{
			kore_log(LOG_AUTH, "No auth key");

			http_response_header(req, "Content-Type", "text/html"); /* for the page */
			http_response(req, 403, "no auth key", strlen("no auth key"));
			kore_free(key);
			return KORE_RESULT_OK;
		}

		/* if(strncmp(key, authorization, strlen(authorization)) != 0) */
		if(strstr(key, authorization) == NULL)
		{
			kore_log(LOG_AUTH, "Invalid auth key [%s]", authorization);

			http_response_header(req, "Content-Type", "text/html"); /* for the page */
			http_response(req, 403, "invalid auth key", strlen("invalid auth key"));
			kore_free(key);
			return KORE_RESULT_OK;
		}
		kore_free(key);

		/* if the auth key was right */

		http_populate_multipart_form(req);


		if((file = http_file_lookup(req, "data")) != NULL)
		{
			ID = snowflake_id();

			asprintf(&IDstr, "serve/%lu%s", (unsigned long)ID, strrchr(file->filename, '.'));




			filew = fopen(IDstr, "ab");
			while((r = http_file_read(file, data, 1024)) > 0)
			{
				fwrite(data, sizeof(unsigned char), r, filew);
			}

			fclose(filew);
			AddHeaders(req);

			if(r == -1)
			{
				kore_log(LOG_ERR, "communication error");
				http_response_header(req, "Content-Type", "text/html"); /* for the page */
				http_response(req, 200, "communication error", strlen("communication error"));
			}
			else
			{
				asprintf(&redir, "%s/%lu%s", URL, (unsigned long)ID, strrchr(file->filename, '.'));
				kore_log(LOG_NOTICE, "File uploaded [%s] [%s]", file->filename, IDstr);
				http_response_header(req, "Content-Type", "text/html"); /* for the page */
				http_response_header(req, "Location", redir);
				http_response(req, 301, redir, strlen(redir));
				free(redir);
			}

			free(IDstr);
		}
		else
		{
			AddHeaders(req);
			http_response_header(req, "Content-Type", "text/html"); /* for the page */
			http_response(req, 400, "file error", strlen("file error"));
		}
	}
	else
	{
		AddHeaders(req);
		http_response_header(req, "Content-Type", "text/html"); /* for the page */
		http_response(req, 200, reply, strlen(reply));
	}
	return KORE_RESULT_OK;
}

int imgsearch(struct http_request *req)
{
	char *finalStr = NULL;
	unsigned char *file = NULL;
	size_t size;


	AddHeaders(req);

	if(strstr(req->path, "~/") || strstr(req->path, "../"))
	{
		http_response(req, 403, "<h1>Please do not traverse paths</h1>", strlen("<h1>Please do not traverse paths</h1>"));
		return KORE_RESULT_OK;
	}

	asprintf(&finalStr, "serve/%s", req->path);

	file = ReadFile(finalStr, &size); /* yes, yes, I know this is terrible. Large files will chow down on ram like no tomorrow */

	if(file != NULL)
	{
		DetectMime(req, req->path);
		http_response(req, 200, file, size);

		kore_free(file);
		return KORE_RESULT_OK;
	}
	else
	{
		http_response(req, 404, "<html><title>not found</title><center><h1>404 file not found</h1></center></html>", strlen("<html><title>not found</title><center><h1>404 file not found</h1></center></html>"));
		return KORE_RESULT_OK;
	}


}

int verify(struct http_request *req, char *data)
{
	return KORE_RESULT_OK;
}
