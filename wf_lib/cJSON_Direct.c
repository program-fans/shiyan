#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <limits.h>
#include <ctype.h>
#include "cJSON.h"

#include "cJSON_Direct.h"

#define KEY_ADDR(obj, offset)  (((unsigned char *)obj) + offset)

#define KEY_ADDR_U8(obj, offset) ((unsigned char *)KEY_ADDR(obj, offset))
#define KEY_ADDR_U16(obj, offset) ((unsigned short *)KEY_ADDR(obj, offset))
#define KEY_ADDR_U32(obj, offset) ((unsigned int *)KEY_ADDR(obj, offset))
#define KEY_ADDR_FLOAT(obj, offset) ((float *)KEY_ADDR(obj, offset))
#define KEY_ADDR_DOUBLE(obj, offset) ((double *)KEY_ADDR(obj, offset))



static void *_cjson2obj(key_info_t *kinfo, cJSON *json, void *obj)
{
	int i,j,cnt;
	cJSON *sub, *item;

	for (i=0;kinfo[i].key != NULL;i++)
	{
		sub = cJSON_GetObjectItem(json,kinfo[i].key);
		if (!sub)
			continue;
		switch(kinfo[i].type)
		{
		case KEY_TYPE_U8:
			*KEY_ADDR_U8(obj, kinfo[i].offset) = sub->valueint;
			break;
		case KEY_TYPE_U16:
			*KEY_ADDR_U16(obj, kinfo[i].offset) = sub->valueint;
			break;
		case KEY_TYPE_U32:
			*KEY_ADDR_U32(obj, kinfo[i].offset) = sub->valueint;
			break;
		case KEY_TYPE_FLOAT:
			*KEY_ADDR_FLOAT(obj, kinfo[i].offset) = sub->valuedouble;
			break;
		case KEY_TYPE_DOUBLE:
			*KEY_ADDR_DOUBLE(obj, kinfo[i].offset) = sub->valuedouble;
			break;
		case KEY_TYPE_STRING:
			strcpy(KEY_ADDR_U8(obj, kinfo[i].offset), sub->string);
			break;
		case KEY_TYPE_ARRAY:
			cnt = cJSON_GetArraySize(sub);
			switch(kinfo[i].arraytype)
			{
			default:
			case KEY_TYPE_STRING:
				printf(" %d Not Support\n", kinfo[i].arraytype);
				break;
			case KEY_TYPE_U8:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						KEY_ADDR_U8(obj, kinfo[i].offset)[j] = item->valueint;
				}
				break;
			case KEY_TYPE_U16:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						KEY_ADDR_U16(obj, kinfo[i].offset)[j] = item->valueint;
				}
				break;
			case KEY_TYPE_U32:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						KEY_ADDR_U32(obj, kinfo[i].offset)[j] = item->valueint;
				}
				break;
			case KEY_TYPE_FLOAT:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						KEY_ADDR_FLOAT(obj, kinfo[i].offset)[j] = item->valuedouble;
				}
				break;
			case KEY_TYPE_DOUBLE:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						KEY_ADDR_DOUBLE(obj, kinfo[i].offset)[j] = item->valuedouble;
				}
				break;
			case KEY_TYPE_OBJECT:
				for (j=0;j<cnt && j<kinfo[i].arraycnt;j++)
				{
					item = cJSON_GetArrayItem(sub, j);
					if (item)
						_cjson2obj(kinfo[i].sub_key, item, KEY_ADDR_U8(obj, kinfo[i].offset) + (kinfo[i].sub_key->csize * j));
				}
				break;
			}
			break;
		case KEY_TYPE_OBJECT:
			_cjson2obj(kinfo[i].sub_key, sub, KEY_ADDR_U8(obj, kinfo[i].offset));
			break;
		}
	}
	return NULL;
}

void *cjson_string2object(key_info_t *kinfo, char *string, void *obj)
{
	cJSON *json = cJSON_Parse(string);

	if (obj == NULL)
		obj = malloc(kinfo[0].csize);
	_cjson2obj(kinfo, json, obj);
	cJSON_Delete(json);
	return obj;
}

static cJSON *_obj2cjson(key_info_t *kinfo, cJSON *json, void *obj)
{
	int i,j;
	cJSON *sub;
	unsigned char *addr;

	for (i=0;kinfo[i].key != NULL;i++)
	{
		switch(kinfo[i].type)
		{
		case KEY_TYPE_U8:
			cJSON_AddNumberToObject(json,kinfo[i].key, *KEY_ADDR_U8(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_U16:
			cJSON_AddNumberToObject(json,kinfo[i].key, *KEY_ADDR_U16(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_U32:
			cJSON_AddNumberToObject(json,kinfo[i].key, *KEY_ADDR_U32(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_FLOAT:
			cJSON_AddNumberToObject(json,kinfo[i].key, *KEY_ADDR_FLOAT(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_DOUBLE:
			cJSON_AddNumberToObject(json,kinfo[i].key, *KEY_ADDR_DOUBLE(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_STRING:
			cJSON_AddStringToObject(json, kinfo[i].key, KEY_ADDR_U8(obj, kinfo[i].offset));
			break;
		case KEY_TYPE_ARRAY:
			switch(kinfo[i].arraytype)
			{
			default:
			case KEY_TYPE_STRING:
				printf(" %d Not Support\n", kinfo[i].arraytype);
				break;
			case KEY_TYPE_U8:
				sub = cJSON_CreateArray();
				for (j=0;j<kinfo[i].arraycnt;j++)
				{
					cJSON_AddItemToArray(sub,cJSON_CreateNumber(KEY_ADDR_U8(obj, kinfo[i].offset)[j]));
				}
				break;
			case KEY_TYPE_U16:
				sub = cJSON_CreateArray();
				for (j=0;j<kinfo[i].arraycnt;j++)
				{
					cJSON_AddItemToArray(sub,cJSON_CreateNumber(KEY_ADDR_U16(obj, kinfo[i].offset)[j]));
				}
				break;
			case KEY_TYPE_U32:
				sub = cJSON_CreateIntArray(KEY_ADDR_U32(obj, kinfo[i].offset), kinfo[i].arraycnt);
				break;
			case KEY_TYPE_FLOAT:
				sub = cJSON_CreateFloatArray(KEY_ADDR_FLOAT(obj, kinfo[i].offset), kinfo[i].arraycnt);
				break;
			case KEY_TYPE_DOUBLE:
				sub = cJSON_CreateDoubleArray(KEY_ADDR_DOUBLE(obj, kinfo[i].offset), kinfo[i].arraycnt);
				break;
			case KEY_TYPE_OBJECT:
				if (kinfo[i].sub_key == NULL)
				{
					printf("ERROR: kinfo[i].sub_key should not be NULL\n");
					break;
				}
				sub = cJSON_CreateArray();
				addr = KEY_ADDR_U8(obj, kinfo[i].offset);
				for (j=0;j<kinfo[i].arraycnt;j++)
				{
					cJSON_AddItemToArray(sub, _obj2cjson(kinfo[i].sub_key, cJSON_CreateObject(), addr + (kinfo[i].sub_key->csize * j)));
				}
				break;
			}
			cJSON_AddItemToObject(json, kinfo[i].key, sub);
			break;
		case KEY_TYPE_OBJECT:
			cJSON_AddItemToObject(json, kinfo[i].key, _obj2cjson(kinfo[i].sub_key, cJSON_CreateObject(), KEY_ADDR(obj, kinfo[i].offset)));
			break;
		}
	}
	return json;
}

char *cjson_object2string(key_info_t *kinfo, void *obj)
{
	cJSON *json = cJSON_CreateObject();
	char *out;

	_obj2cjson(kinfo, json, obj);

	out = cJSON_Print(json);
	cJSON_Delete(json);
	return out;
}


#if 0
typedef struct tagRECT
{
	unsigned int		x;
	unsigned int		y;
	unsigned int		w;
	unsigned int		h;
}RECT, *PRECT;


static key_info_t rect_key[] = {
	MAKE_KEY_INFO(RECT, KEY_TYPE_U32, x, NULL),
	MAKE_KEY_INFO(RECT, KEY_TYPE_U32, y, NULL),
	MAKE_KEY_INFO(RECT, KEY_TYPE_U32, w, NULL),
	MAKE_KEY_INFO(RECT, KEY_TYPE_U32, h, NULL),
	MAKE_END_INFO()
};

typedef struct tagMD
{
	int			bEnable;			//是否开启移动检测
	unsigned int	nSensitivity;		//灵敏度
	unsigned int	nThreshold;			//移动检测阈值
	unsigned int	nRectNum;			//移动检测区域个数，最大为4，0表示全画面检测
	RECT		stRect[4];

	unsigned int	nDelay;
	unsigned int	nStart;
	unsigned int	bOutClient;
	unsigned int	bOutEMail;
	unsigned char testlist[5];
	RECT		testObj;
	char name[20];
	float flt;
	double db;
	float flta[3];
	double dba[3];
}MD, *PMD;

static key_info_t md_key[] = {
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, bEnable, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, nSensitivity, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, nThreshold, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, nRectNum, NULL),
	MAKE_ARRAY_INFO(MD, KEY_TYPE_ARRAY, stRect, rect_key, 4, KEY_TYPE_OBJECT),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, nStart, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, bOutClient, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_U32, bOutEMail, NULL),
	MAKE_ARRAY_INFO(MD, KEY_TYPE_ARRAY, testlist, NULL, 5, KEY_TYPE_U8),
	MAKE_KEY_INFO(MD, KEY_TYPE_OBJECT, testObj, rect_key),
	MAKE_KEY_INFO(MD, KEY_TYPE_STRING, name, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_FLOAT, flt, NULL),
	MAKE_KEY_INFO(MD, KEY_TYPE_DOUBLE, db, NULL),
	MAKE_ARRAY_INFO(MD, KEY_TYPE_ARRAY, flta, NULL, 3, KEY_TYPE_FLOAT),
	MAKE_ARRAY_INFO(MD, KEY_TYPE_ARRAY, dba, NULL, 3, KEY_TYPE_DOUBLE),
	MAKE_END_INFO()
};

void cjson_direct_test(void)
{
	char *out;
	MD md = 
	{
		1,	//bEnable;	
		30,	//nSensitivity;
		40,	//nThreshold;
		4,	//nRectNum;	
		{
			{1,2,3,4},
			{2,3,4,5},
			{3,4,5,6},
			{4,5,6,7},
		},
		10,	//nDelay;
		10,	//nStart;
		1,	//bOutClient
		1,	//bOutEMail
		{1,2,3,4,5},
		{1,2,3,4},
		"I have a dream",
		0.1,
		0.2,
		{2.1,3,2},
		{3.1,4,3}
	};
	MD m2;

	out = cjson_object2string(md_key,(void *)&md);
	printf("out: \n%s\n", out);
	cjson_string2object(md_key, out, (void *)&m2);
	free(out);
	out = cjson_object2string(md_key,(void *)&m2);
	printf("out: \n%s\n", out);
	free(out);
}
#endif

