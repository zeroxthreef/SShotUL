#include <kore/kore.h>
#include <kore/http.h>

#include <openssl/sha.h>
#include <jansson.h>

#include <ctype.h>
#include <dirent.h>
#include <sys/statvfs.h>

#include "assets.h"

#include "snowflake.h"


#define URL "https://ssul.vertesine.com"

#define MESSAGE_ID 413


typedef struct
{
  char *mime;
  char *extension;
} mime_t;

typedef struct
{
  char *ext;
  size_t size;
  size_t count;
} file_t;

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

file_t *files = NULL;

size_t fileCount;

/* const char *reply = "<html><meta name=\"description\" content=\"Terrible screenshot/file uploading service\"><meta name=\"DC.title\" content=\"SSUL File Uploading Thing\"><title>SShotUL</title><center><h1>Screen Shot Uploader</h1><br><center>This is only for me lol. If you want the auth key, email me at zeroxthreef@gmail.com</center></center><br><br><marquee>you can find this on github at <a href=\"https://github.com/zeroxthreef/SShotUL\">this link</a></marquee></html>"; */

int	home(struct http_request *);

int	upload(struct http_request *);

int	imgsearch(struct http_request *);

int errorPage(struct http_request *req, int code, char *description);

void update_list(struct kore_msg *msg, const void *data);

/* functions */

size_t GetFileSize(char *path)
{
  size_t size;
  FILE *f;

  f = fopen(path, "rb");
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  rewind(f);

  fclose(f);
  return size;
}

uint8_t *ReadFile(char *location, unsigned long *sizePtr, unsigned long *fullSizePtr, unsigned long offset, unsigned long askSize, char isString) /* from my vertesine backend again */
{
  FILE *f;
  unsigned long size;
  uint8_t *dataPtr;
  f = fopen(location, "rb");
  if(f == NULL){
    //printf("Error cant find\n");
    return (uint8_t *)NULL;
  }

	if(fullSizePtr != NULL)
	{
		fseek(f ,0, SEEK_END);
	  *fullSizePtr = ftell(f);
	  rewind(f);
	}


	if(offset)
	{
		fseek(f, 0, SEEK_END);
		if(askSize)
			size = askSize;
		else
			size = ftell(f) - offset;

		fseek(f, offset, SEEK_SET);
	}
	else
	{
		fseek(f, 0, SEEK_END);
		if(askSize)
			size = askSize;
		else
			size = ftell(f);
		rewind(f);
	}


	if(isString)
	{
		dataPtr = (uint8_t *)kore_malloc(size + 1);
		dataPtr[size + 1] = 0x00;
	}
	else
		dataPtr = (uint8_t *)kore_malloc(size);


  fread(dataPtr, sizeof(unsigned char), size, f);

  if(dataPtr == NULL){
    kore_log(LOG_CRIT, "Could not allocate memory");
    return (uint8_t *)NULL;
  }

	rewind(f);
  fclose(f);

  *sizePtr = size;
  return dataPtr;
}

short TestFileExists(char *path)
{
	FILE *f;
	f = fopen(path, "rb");
	if(f == NULL)
	{
		return 0;
	}
	else
	{
		fclose(f);
		return 1;
	}
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
	http_response_header(req, "Accept-Ranges", "bytes");/* TODO fix*/
	http_response_header(req, "Server", "SSUL");
}

void scanFiles() /* gave up a better way of doing it for this. It works ok so whatever */
{
  DIR *dir;
  struct dirent *dire;
  struct statvfs fdata;
  char *tempstr;
  size_t i;
  int found = 0;


  dir = opendir("serve");
  if(dir)
  {
    while((dire = readdir(dir)) != NULL)
    {
      /* printf("[DIRECTORY PLACE FILE INIT]%s\n", dire->d_name); */

      //dire->d_name


      //tempfile.ext



      if(fileCount == 0)/* add the first file */
      {
        printf("adding first file\n");
        if(strcmp(dire->d_name, ".") == 0 || strcmp(dire->d_name, "..") == 0 || strrchr(dire->d_name, '.') == NULL)
        {
          /* not adding file */
          printf("not adding [%s]\n", dire->d_name);
        }
        else
        {
          printf("adding [%s]\n", dire->d_name);
          files[fileCount].ext = kore_strdup(strrchr(dire->d_name, '.'));
          files[fileCount].count = 1;
          asprintf(&tempstr, "serve/%s", dire->d_name);
          files[fileCount].size = GetFileSize(tempstr);
          fileCount = 1;

          free(tempstr);
        }

      }
      else /* add every file that follows. SCANE HERE TOO */
      {
        if(strcmp(dire->d_name, ".") == 0 || strcmp(dire->d_name, "..") == 0 || strrchr(dire->d_name, '.') == NULL)
        {
          /* not adding file */
          printf("not adding [%s]\n", dire->d_name);
        }
        else
        {
          //printf("adding [%s]\n", dire->d_name);
          /* search for file first */

          for(i = 0; i < fileCount; i++)
          {
            if(strcmp(files[i].ext, strrchr(dire->d_name, '.')) == 0)
            {
              printf("found %s\n", files[i].ext);

              asprintf(&tempstr, "serve/%s", dire->d_name);
              files[i].size += GetFileSize(tempstr);
              files[i].count++;
              free(tempstr);
              found = 1;
              break;

            }
            else
            {
              found = 0;
            }
          }
          printf("found: %d\n", found);
          if(!found)
          {
            files = kore_realloc(files, sizeof(file_t) * (fileCount + 1));
            if(files == NULL)
            {
              kore_log(LOG_CRIT, "mem error");
            }
            printf("not found, adding %s\n", dire->d_name);
            files[fileCount].ext = kore_strdup(strrchr(dire->d_name, '.'));
            files[fileCount].count = 1;

            asprintf(&tempstr, "serve/%s", dire->d_name);
            files[fileCount].size = GetFileSize(tempstr);
            fileCount++;


            free(tempstr);
          }
        }

      }

    }
    close(dir);
  }
  else
  {
    kore_log(LOG_CRIT, "dir scan error");
  }
  printf("TOTAL: %lu\n", fileCount);
}

void update_list(struct kore_msg *msg, const void *data) /* awesome. This never gets called. Whatever */
{
  printf("message\n");
  if(strcmp(data, "update") == 0)
    scanFiles();
  /* update and search the directory */
}

/* serve things */

int sshotul_load(int state)
{

	if(state != KORE_MODULE_UNLOAD)
	{
    /* TODO LIST
    *
    * make main json file for referrer, views, and other stats
    * page generation with the same main file stats listed above. Maybe future, traffig graph
    * page comments stored inside the json settings for the file.
    * add main config file that has option to return the page with comments and stuff or just the resource. Need to add the embed stuff to the generated pages
    * possibly generate new pages on worker startup(maybe risky cause processes, or maybe make a task do it) for files that are added externally
    *
    */


    if(kore_msg_register(MESSAGE_ID, update_list) != KORE_RESULT_OK)
    {
      kore_log(LOG_CRIT, "there will be terrible errors");
    }


    fileCount = 0;

		kore_log(LOG_NOTICE, "initializing sshotul");
		snowflake_init(0, 0);

    /* do the initial file adding */

    files = kore_malloc(sizeof(file_t));


    /* do thing */
    scanFiles();
	}


	return KORE_RESULT_OK;
}

int home(struct http_request *req)
{
  char *tableContainer = "%s - <br><hr></hr><table>%s</table>";
  char *tableRow = "<tr><th>%s</th><th>%s</th><th>%s</th></tr>%s";
  char *temptable;
  char *temptableline;
  char *oldTemptable;
  char *temptable0;
  char *temptable1;
  char *directoryTable;
  char *fileTable;
  char *finalElement;
  struct kore_buf *reply;
  size_t length;
  size_t i;
  unsigned char *reply_str;
  DIR *dir;
  struct dirent *dire;
  struct statvfs fdata;

	AddHeaders(req);
	http_response_header(req, "Content-Type", "text/html"); /* for the page */

  reply = kore_buf_alloc(asset_len_home_html);
  kore_buf_append(reply, asset_home_html, asset_len_home_html);

  /* create table */
  /*
  dir = opendir("serve");
  if(dir)
  {
    while((dire = readdir(dir)) != NULL)
    {
      printf("%s\n", dire->d_name);
    }
    close(dir);
  }
  else
  {
    kore_buf_replace_string(reply, "[STAT_TABLE]", "dir error", strlen("dir error"));
  }
  */
  /* thought of a much hackier, but easier way to do this with jansson*/

  /* generate direcory statistics table */
  char *tempThing0;
  char *tempThing1;
  statvfs("serve", &fdata);

  asprintf(&tempThing0, "%lu", fdata.f_bsize);
  asprintf(&tempThing1, "%lu", (unsigned long)fdata.f_bavail);


  asprintf(&temptable, tableRow, "Directory", "Used", "Free", "%s");
  asprintf(&temptable0, temptable, tableRow);
  asprintf(&temptable1, temptable0, "serve", tempThing0, tempThing1, "");

  free(tempThing0);
  free(tempThing1);

  asprintf(&directoryTable, tableContainer, "Usage", temptable1);

  free(temptable);
  free(temptable0);
  free(temptable1);




  /* generate file type statistics */
  /* TODO make a signal to other workers to add a struct entry to the disk cache thing and each worker uses the upload point to cache and send signal */



  asprintf(&temptable, tableRow, "Extension", "Amount", "Bytes On Disk", "%s");


  for(i = 0; i < fileCount; i++)
  {
    oldTemptable = temptable;

    /* change numbers into strings */
    asprintf(&temptable0, "%lu", files[i].count);
    asprintf(&temptable1, "%lu", files[i].size);
    asprintf(&temptableline, tableRow, files[i].ext, temptable0, temptable1, "%s");

    asprintf(&temptable, temptable, temptableline);

    free(oldTemptable);
    free(temptable0);
    free(temptable1);
    free(temptableline);
  }

  oldTemptable = temptable;
  asprintf(&temptable, temptable, "");
  free(oldTemptable);
  printf("%s\n", temptable);
  asprintf(&fileTable, tableContainer, "Types", temptable);

  asprintf(&finalElement, "%s<br>%s", directoryTable, fileTable);

  /* put evberything into the finalelement */



  kore_buf_replace_string(reply, "[STAT_TABLE]", finalElement, strlen(finalElement));

  reply_str = kore_buf_release(reply, &length);

	http_response(req, 200, reply_str, length);


  free(directoryTable);
  free(finalElement);
  kore_free(reply_str);
	/*

	char *key;
	size_t size;
	key = ReadFile("key.txt", &size, NULL, 1, 3, 1);
	printf("a[%s]\n", key);
	*/
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
  //file_t *tempPtrFile;



	AddHeaders(req);

	key = ReadFile("key.txt", &size, NULL, 0, 0, 1);

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
			http_response(req, 403, "invalid auth key", strlen("invalid auth key")); /* wont change this to the error handler to make debugging easier */
			kore_free(key);
			return KORE_RESULT_OK;
		}
		kore_free(key);

		/* if the auth key was right */

		http_populate_multipart_form(req);


		if((file = http_file_lookup(req, "data")) != NULL)
		{
      size_t total = 0;
      char *tempStr;
      char tempStr1[20];
      char *finalTemp;
			ID = snowflake_id();


      asprintf(&tempStr, "%lu", (unsigned long)ID);

      SHA1(tempStr, strlen(tempStr), tempStr1);

      kore_base64_encode(tempStr1, 20, &finalTemp);

      finalTemp[strlen(finalTemp) - 1] = 0x00; /* get rid of the = */

			/* asprintf(&IDstr, "serve/%lu%s", (unsigned long)ID, strrchr(file->filename, '.')); */
      asprintf(&IDstr, "serve/%s%s", finalTemp, strrchr(file->filename, '.'));




			filew = fopen(IDstr, "ab");
			while((r = http_file_read(file, data, 1024)) > 0)
			{
        total += r;
				fwrite(data, sizeof(unsigned char), r, filew);
			}

      //tempPtrFile = kore_malloc(sizeof(file_t));

      //tempPtrFile->size = total;

			fclose(filew);
			AddHeaders(req);

			if(r == -1)
			{
				kore_log(LOG_ERR, "communication error");
				errorPage(req, 400, "communication error");
			}
			else
			{
        /* if it's successful, do all the things */
        /* update list of files */

        //tempPtrFile->ext = kore_strdup(strrchr(file->filename, '.')); /* yeah, im breaking my comment style here. I dont care anymore */
        //tempPtrFile->count = 1; /* really isnt needed */

        //kore_msg_send(KORE_MSG_WORKER_ALL, MESSAGE_ID, (void *)tempPtrFile, sizeof(file_t));
        kore_msg_send(KORE_MSG_WORKER_ALL, MESSAGE_ID, "update", strlen("update"));


				asprintf(&redir, "%s/%lu%s", URL, (unsigned long)ID, strrchr(file->filename, '.'));
				kore_log(LOG_NOTICE, "File uploaded [%s] [%s]", file->filename, IDstr);
				http_response_header(req, "Content-Type", "text/html"); /* for the page */
				http_response_header(req, "Location", redir);
				http_response(req, 301, redir, strlen(redir));
				free(redir);
			}

			free(IDstr);
      free(tempStr);
      kore_free(finalTemp);
		}
		else
		{
			AddHeaders(req);
			return errorPage(req, 400, "file error");
		}
	}
	else
	{
		home(req);
	}
	return KORE_RESULT_OK;
}

int imgsearch(struct http_request *req)
{
	unsigned long rangeBegin = 0;
	unsigned long rangeEnd = 0;
	char *contentRange = NULL;
	char *finalStr = NULL;
	unsigned char *file = NULL;
	size_t size;
	size_t finalSize;


	AddHeaders(req);

	if(strstr(req->path, "~/") || strstr(req->path, "../"))
	{

		return errorPage(req, 403, "Please dont try and traverse paths. That makes the computer sad");
	}

	asprintf(&finalStr, "serve/%s", req->path);



	if(TestFileExists(finalStr))
	{
		char *range = NULL;


		/* parse ranges if provided */
		http_request_header(req, "Range", &range);

		if(range == NULL) /* if no range requested */
		{
			/* printf("regular serve\n"); */ /* Ive left these debug messages scattered around and I dont feel like fixing it anymore */

			file = ReadFile(finalStr, &size, NULL, 0, 0, 0); /* yes, yes, I know this is terrible. Large files will chow down on ram like no tomorrow */
			DetectMime(req, req->path);
			http_response(req, 200, file, size);
			kore_free(file);
		}
		else /* if range was requested */
		{
			if(strncmp(range, "bytes=", strlen("bytes=")) == 0) /* http_response_header(req, "Content-Range", "text/html"); */
			{
				printf("%s\n", range);
				file = ReadFile(finalStr, &finalSize, &size, 0, 1, 0);


				/* actually parse the client's request */
				if(range[strlen("bytes=") + 1] != 0x00) /* make sure the client isnt trying to mess with the server */
					rangeBegin = strtoul(&range[strlen("bytes=")], NULL, 10);
				else
				{
					kore_log(LOG_ALERT, "invalid byte in range string provided. Terminated early");
					http_response_header(req, "Content-Type", "text/html"); /* for the page */
					kore_free(file);
					return errorPage(req, 400, "bad ranges");
				}

				/* parse second number */

				char *dash = strchr(range, '-');
				if(dash == NULL)
				{
					kore_log(LOG_ALERT, "invalid range string format division");
					http_response_header(req, "Content-Type", "text/html"); /* for the page */
					kore_free(file);
					return errorPage(req, 400, "bad ranges");
				}

				if(dash[1] == 0x00)
				{
					rangeEnd = size;
				}
				else
				{
					rangeEnd = strtoul(dash + 1, NULL, 10);
				}

				if(rangeBegin > size || rangeEnd > size || rangeEnd < rangeBegin)
				{
					kore_log(LOG_ALERT, "invalid range string byte sizes");
					http_response_header(req, "Content-Type", "text/html"); /* for the page */
					/* http_response_stream(struct http_request *, int, void *, size_t, int (*cb)(struct netbuf *), void *) */
					kore_free(file);
					return errorPage(req, 400, "bad ranges");
				}

				kore_free(file);
				file = ReadFile(finalStr, &size, &finalSize, rangeBegin, rangeEnd - rangeBegin, 0);

				asprintf(&contentRange, "bytes %lu-%lu/%lu", rangeBegin, rangeEnd, finalSize);

				if(contentRange == NULL)
				{
					kore_log(LOG_ERR, "Couldnt respond with content range header");
					http_response_header(req, "Content-Type", "text/html"); /* for the page */
					kore_free(file);
					return errorPage(req, 500, "fatal server error");
				}
				/* finalSize = rangeEnd - rangeBegin; */
				printf("%s then %lu then %lu\n", contentRange, size, finalSize);

				DetectMime(req, req->path);



				http_response_header(req, "Content-Range", contentRange); /* add the content range header */
				http_response(req, 206, file, size);

				kore_free(file);
			}
			else
			{
				kore_log(LOG_ALERT, "Bad range header");
				return errorPage(req, 400, "bad ranges");
			}
		}





		return KORE_RESULT_OK;
	}
	else
	{
		return errorPage(req, 404, "file not found");
	}


}

int errorPage(struct http_request *req, int code, char *description)
{
  struct kore_buf *reply;
  size_t length;
  unsigned char *reply_str;

  char *string;

  asprintf(&string, "%d %s", code, description);



	AddHeaders(req);
	http_response_header(req, "Content-Type", "text/html"); /* for the page */

  reply = kore_buf_alloc(asset_len_error_html);
  kore_buf_append(reply, asset_error_html, asset_len_error_html);

  kore_buf_replace_string(reply, "[ERROR]", string, strlen(string));

  reply_str = kore_buf_release(reply, &length);

	http_response(req, code, reply_str, length);
  kore_free(reply_str);
  free(string);
	return KORE_RESULT_OK;
}

int verify(struct http_request *req, char *data)
{
	return KORE_RESULT_OK;
}
