/*
  $Id: ac_timer.c,v 1.4 2014/11/09 13:36:37 licj Exp $
  $Author: licj $
  $Date: 2014/11/09 13:36:37 $
  $Log: ac_timer.c,v $
  Revision 1.4  2014/11/09 13:36:37  licj
  *** empty log message ***

*/
#include <semaphore.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <time.h>
#include <signal.h>

#include "ac_timer.h"

#define MAX_BUCKET_SIZE       8192		/*Timer µÄBucketÍ°Éî±£Ö¤Á½¸öG¡Ê±µÄ¶¨Ê±*/

#define BUCKET_MASK                (MAX_BUCKET_SIZE-1)

/*µ¥¸ö¶¨Ê±Æ÷*/
typedef struct timerEvent
{
	struct timerEvent *pNext; 
	struct timerEvent *pre; 
	int timerValue;                /*¶à³¤Ê±¼äsec*/
	int key;                                 /*Ê¶±gtimerµÄ¹Ø¼ü×Ö*/
	int (*callBack)(void*,int); /*³¬Ê±»Øµ÷Ö´GGº¯Êi*/
	void *arg1;                          /*²ÎÊi*/
	int arg2;                               /*²ÎÊi³¤¶È*/
	int if_reop;                           /*0±íÊ¾Ö»Ö´GGÒ»´Î£¬1¼ÌGøÑ­»·*/
}TIMER_EVENT;

/*µ¥¸ö¹sÏ£Í°*/
typedef struct timer_head
{
	TIMER_EVENT *bucket_head;
	TIMER_EVENT *bucket_tail;
	int bucket_timerNum;                     /*µ±Ç°Í°ÓG¶àÉÙ¸ö¶¨Ê±Æ÷*/
	
}TIMER_HEAD;

/*ÈÎÎñ´¦ÀíÁ´±í*/
struct timer_task
{
	TIMER_EVENT *task_head;
	TIMER_EVENT *task_tail;
	
};

struct bucket_key_manger{
	int if_user;			/*ÊÇ·ñÔÚÊ¹ÓÃ*/	
	int bucket;                          /*ÊôÓÚÄÄÒ»¸öhashÍ°*/ 
};

/*Private Members*/
static TIMER_HEAD *gTimerBucket = NULL;	/*Timer BucketµÄÊ×µØÖ·*/
static struct timer_task gTimertask ;	/*ÈÎÎñÔËÐÐÁ´±íÊ×µØÖ·*/
static int gCurBucket = 0;				/*µ±Ç°Ö¸ÏòµÄTimer Bucket*/
static int gTimerIsRunning = 0;		/*Timer´¦ÀíÈÎÎñÊÇ·ñÔÚÔËÐÐ*/
static pthread_mutex_t gTimerBucket_mutex; /*Timer bucket Ëø*/
static sem_t gTimerSemID;	                 /*TimerÈÎÎñÍ¬²½ÐÅºÅÁ¿*/
static sem_t gTimerBucketSemID;          /*hashÍ°Í£Ö¹Ñ­»·ÐÅºÅ*/
static sem_t gTimertaskSemID;                   /*ÈÎÎñÍ£Ö¹Í¨ÖªÐÅºÅ*/
static pthread_t gTimerBucket_thread_id;
static pthread_t gTimertask_thread_id;
static struct bucket_key_manger *key_manger;/*keyÖµ¹ÜÀí*/

//extern int ac_if_run;
//extern void sig_exit(int signo);
static void timerAddToBucket(int bucket, TIMER_EVENT *pTimer);
	
static int mysleep(int second,long nsec){
	if(second==0 && nsec ==0)
		return -1;
	sigset_t sigset;
	if(sigemptyset(&sigset) == -1){
		//ACCW_LOG("sigset init filed");
		return -1;
	}
	if(sigaddset(&sigset,SIGALRM) == -1){
		//ACCW_LOG("SIGALRM added sigset filed");
		return -1;
	}
	/*
	if(sigaddset(&sigset,SIGTERM) == -1){
		return -1;
	}
	*/
	struct timespec timeout;
	timeout.tv_sec = second;
	timeout.tv_nsec = nsec;
	return pselect(0, NULL, NULL, NULL, &timeout,&sigset);
}
static TIMER_EVENT * timer_task_get_tail(){

	TIMER_EVENT *temp = NULL;
	if(gTimertask.task_tail == NULL){
		temp = NULL;
	}else{
		if(gTimertask.task_tail == gTimertask.task_head){
			temp = gTimertask.task_tail;
			gTimertask.task_tail = gTimertask.task_head = NULL;
		}else{
			temp = gTimertask.task_tail;
			gTimertask.task_tail = temp->pre;
			gTimertask.task_tail->pNext = NULL;
			
		}
		temp->pre =NULL;
		temp->pNext = NULL;
	}

	return temp;
}
static void timer_task_Process(){
	TIMER_EVENT *temp = NULL;
	while(1){
		sem_wait(&gTimerSemID);
		if(gTimerIsRunning == 0)
			break;
		pthread_mutex_lock(&gTimerBucket_mutex);
		if((temp = timer_task_get_tail()) == NULL){
			pthread_mutex_unlock(&gTimerBucket_mutex);
			continue;
		}
		else{	
			//Ö´ÐÐ»Øµ÷º¯Êý
			pthread_mutex_unlock(&gTimerBucket_mutex);
			(*temp->callBack)(temp->arg1,temp->arg2);
			pthread_mutex_lock(&gTimerBucket_mutex);

		}
		
		if(temp->if_reop){//¼ÌÐøÑ­»·
			int selectBucket = (gCurBucket + temp->timerValue) & (BUCKET_MASK);
			key_manger[temp->key].bucket = selectBucket;
			timerAddToBucket(selectBucket,temp);
		}else{
			if(temp->arg2 > 0)
				free(temp->arg1);
			free(temp);
		}
		temp = NULL;
		pthread_mutex_unlock(&gTimerBucket_mutex);
	}
	/*Çå³ýÈÎÎñÖÐËùÓÐµÄ¶¨Ê±Æ÷*/
	pthread_mutex_lock(&gTimerBucket_mutex);
	temp = gTimertask.task_head;
	TIMER_EVENT *p = NULL;
	while(temp){
		p = temp->pNext;
		if(temp->arg2 > 0)
			free(temp->arg1);
		free(temp);
		temp = p;
	}
	gTimertask.task_head = NULL;
	gTimertask.task_tail = NULL;
	pthread_mutex_unlock(&gTimerBucket_mutex);
	sem_post(&gTimertaskSemID);  //Ïß³Ì½áÊøÍ¨Öª
	return;
}
static void timerAddToBucket(int bucket, TIMER_EVENT *pTimer)
{
	if (gTimerBucket == NULL || gTimerIsRunning == 0) {
		return;
	}	
	TIMER_EVENT * pHeadTimer = gTimerBucket[bucket].bucket_head;
	if(pHeadTimer == NULL){
		gTimerBucket[bucket].bucket_head = pTimer;
		gTimerBucket[bucket].bucket_tail = pTimer;
	}else{
		pTimer->pNext = pHeadTimer;
		pHeadTimer->pre = pTimer;
		gTimerBucket[bucket].bucket_head = pTimer;
	}
	
	gTimerBucket[bucket].bucket_timerNum ++;

}

int timerAdd(int second,int (*callBack)(void*,int), void *user_data,int len,int if_reop)
{
	int selectBucket = 0;
	int bucketMask = MAX_BUCKET_SIZE - 1;
	TIMER_EVENT *pTimer;
	int key = 0;
	if ((pTimer = (struct timerEvent *)malloc(sizeof(struct timerEvent))) == NULL)
	{
		return -1;		
	}
	memset(pTimer, 0, sizeof(TIMER_EVENT));
	pTimer->callBack = callBack;
	pTimer->timerValue = second;
	pTimer->if_reop = if_reop;
	if(user_data != NULL) {

		if(len > 0){
			pTimer->arg1 = malloc(len);
			if(pTimer->arg1 == NULL){
				free(pTimer);
				return -1;
			}
			memcpy(pTimer->arg1, user_data, len);
			pTimer->arg2= len;
		}else
			pTimer->arg1 = user_data;
	}
	
	/*Í¨¹ý"Óë",ÊµÏÖÁËselect_bucket³¬¹ýbucket_mask Ê±,×Ô¶¯»ØÈÆ. */
	selectBucket = (gCurBucket + second) & (BUCKET_MASK);
	if (gTimerBucket == NULL || gTimerIsRunning == 0) {
		if (pTimer->arg2) {
			free(pTimer->arg1);
		}
		return -1;
	}
	pthread_mutex_lock(&gTimerBucket_mutex);
	while(key < MAX_TIMER_SIZE){
		if(key_manger[key].if_user == 0)
			break;
		key ++;
	}
	key_manger[key].if_user = 1;
	key_manger[key].bucket = selectBucket;
	pTimer->key = key;
	timerAddToBucket(selectBucket,pTimer);
	
	pthread_mutex_unlock(&gTimerBucket_mutex);

	return key;
}

void timerStop(int key)
{
	TIMER_EVENT *pTimer = NULL;
	int selectBucket = 0;
	
	pthread_mutex_lock(&gTimerBucket_mutex);
	/*²éÕÒ¸ÃtimerÊÇ·ñ´æÔÚ*/
	if(key_manger[key].if_user == 0){
		pthread_mutex_unlock(&gTimerBucket_mutex);
		return;
	}
	/*ÏÈÔÚhashÍ°ÀïÕÒ*/
	selectBucket = key_manger[key].bucket;
	key_manger[key].bucket = 0;
	key_manger[key].if_user = 0;
	pTimer = gTimerBucket[selectBucket].bucket_head;
	while(pTimer)
	{
		if(pTimer->key == key)
		{
			if(pTimer == gTimerBucket[selectBucket].bucket_head){//=head
				if(pTimer == gTimerBucket[selectBucket].bucket_tail){
					gTimerBucket[selectBucket].bucket_head = NULL;
					gTimerBucket[selectBucket].bucket_tail = NULL;
				}else{
					gTimerBucket[selectBucket].bucket_head = pTimer->pNext;
					pTimer->pNext->pre = NULL;
				}
			}else if(pTimer == gTimerBucket[selectBucket].bucket_tail){
				
				gTimerBucket[selectBucket].bucket_tail = pTimer->pre;
				pTimer->pre->pNext = NULL;
			}else{       //zhongjian
				pTimer->pNext->pre = pTimer->pre;
				pTimer->pre->pNext = pTimer->pNext;
				
			}
			break;
		}
		pTimer = pTimer->pNext;
	}
	if(pTimer == NULL){// ¼ÌÐøÔÚÈÎÎñÁ´ÀïÃæÕÒ
		pTimer = gTimertask.task_head;
		while(pTimer){
			if(pTimer->key == key){
				if(pTimer == gTimertask.task_head){
					if(pTimer == gTimertask.task_tail){
						gTimertask.task_tail = NULL;
						gTimertask.task_head = NULL;
					}else{
						gTimertask.task_head = pTimer->pNext;
						pTimer->pNext->pre = NULL;
					}
				}else if(pTimer == gTimertask.task_tail){
					gTimertask.task_tail = pTimer->pre;
					pTimer->pre->pNext = NULL;
				}else{
					pTimer->pNext->pre = pTimer->pre;
					pTimer->pre->pNext = pTimer->pNext;
				}
				break;
			}
			
			pTimer = pTimer->pNext;
		}
	}
	if(pTimer == NULL){
		pthread_mutex_unlock(&gTimerBucket_mutex);
		return;
	}else{
		if(pTimer->arg2 > 0)
			free(pTimer->arg1);
		free(pTimer);
		pTimer = NULL;
	}
	pthread_mutex_unlock(&gTimerBucket_mutex);
	return;
}

/********************************************************************************
 * ¹¦ÄÜ     : ¶¨Ê±Æ÷¼ì²éº¯Êý£¬½«¶¨Ê±µ½µÄÊÂ¼þJIA Èçµ½ÈÎÎñ¶ÓÁÐ
 *    
 * ²ÎÊý     : 
 * [IN] 
 *   ÎÞ
 *   
 * [OUT]
 *   ÎÞ
 * 
 * ·µ»ØÖµ   : 
 *   ÎÞ
 *   
*******************************************************************************/  
static void timerProcess(void)
{
	TIMER_EVENT *phead = NULL;
	TIMER_EVENT *ptail = NULL;
	TIMER_EVENT *temp = NULL;
	int timer_num = 0;
	int selectBucket = 0;

	while(gTimerIsRunning)
	{
		
			
		sleep(1);/*Ãë¼¶Ê±¼ä¾«¶È*/
		//mysleep(1,0);//850000000
		//if(gTimerIsRunning == 0 ||ac_if_run == 0)
		if(gTimerIsRunning == 0 )
			break;
		pthread_mutex_lock(&gTimerBucket_mutex);
		phead = gTimerBucket[gCurBucket].bucket_head;
		ptail = gTimerBucket[gCurBucket].bucket_tail;
		/*½«ËùÓÐ³¬Ê±µÄTimer¶ÔÓ¦µÄÊÂ¼þ¼ÓÈëµ½ÊÂ¼þ¶ÓÁÐÖÐ*/
		if(phead && ptail)
		{	/*ÏÂÁ´²Ù×÷*/
			gTimerBucket[gCurBucket].bucket_head = NULL;
			gTimerBucket[gCurBucket].bucket_tail = NULL;
			timer_num = gTimerBucket[gCurBucket].bucket_timerNum;
			gTimerBucket[gCurBucket].bucket_timerNum = 0;
			/*ÉÏÁ´²Ù×÷*/
			if(gTimertask.task_tail == NULL){/*KONG lian*/
				gTimertask.task_head = phead;
				gTimertask.task_tail = ptail;

			}else{
				ptail->pNext = gTimertask.task_head;
				gTimertask.task_head->pre = ptail;
				gTimertask.task_head = phead;
			}
		}
		while(timer_num){
			sem_post(&gTimerSemID);
			timer_num --;
		}
		pthread_mutex_unlock(&gTimerBucket_mutex);
		
		/*Í¨¹ý"Óë",ÊµÏÖÁËg_garpCurBucket³¬¹ýbucket_mask Ê±,×Ô¶¯»ØÈÆ*/
		gCurBucket = (gCurBucket + 1) & BUCKET_MASK; 

	}
	/*Ïß³ÌÍË³ö*/
	
	pthread_mutex_lock(&gTimerBucket_mutex);
	int i;
	for(i = 0; i<MAX_BUCKET_SIZE; i++){
		phead = gTimerBucket[i].bucket_head;
		while(phead){
			ptail = phead->pNext;
			if(phead->arg2 > 0)
				free(phead->arg1);
			free(phead);
			phead = ptail;
		}
		gTimerBucket[i].bucket_head = NULL;
		gTimerBucket[i].bucket_tail= NULL;
	}	
	pthread_mutex_unlock(&gTimerBucket_mutex);
	sem_post(&gTimerBucketSemID);  //Ïß³Ì½áÊøÍ¨Öª
	//if (ac_if_run == 0)
		//sig_exit(0);
	return ;
}

int timerTaskStart(int isStart)
{
	if (isStart)
	{
		if (gTimerIsRunning)
		{
			return 0;
		}
                gTimerBucket = NULL;
                gCurBucket = 0;	
                memset(&gTimertask,0,sizeof(struct timer_task));
                key_manger = NULL;
		gTimerIsRunning = 1;

		if ((gTimerBucket = (struct timer_head *)malloc(MAX_BUCKET_SIZE * sizeof(TIMER_HEAD))) == NULL)
		{
			goto Timer_out;		
		}
		memset(gTimerBucket, 0, MAX_BUCKET_SIZE * sizeof(TIMER_HEAD));

		if((key_manger = (struct bucket_key_manger *)malloc(MAX_TIMER_SIZE*sizeof(struct bucket_key_manger))) == NULL){

			goto Timer_out;
		}
		pthread_mutex_init(&gTimerBucket_mutex, NULL); 


		if(sem_init(&gTimerSemID, 0, 0)!=0) //Í¬²½ÐÅºÅÁ¿³õÊ¼»¯
		{
			goto Timer_out;
		}
		if(sem_init(&gTimerBucketSemID, 0, 0)!=0) //ÐÅºÅÁ¿³õÊ¼»¯
		{
			goto Timer_out;
		}
		if(sem_init(&gTimertaskSemID, 0, 0)!=0) //ÐÅºÅÁ¿³õÊ¼»¯
		{
			goto Timer_out;
		}
		gCurBucket = 0;

		pthread_attr_t thread_attr;
		pthread_attr_init(&thread_attr);
		pthread_attr_setdetachstate(&thread_attr,PTHREAD_CREATE_DETACHED);
		/*´´½¨Ò»¸ö¶¨Ê±Ïß³Ì*/
		if (pthread_create(&gTimerBucket_thread_id,&thread_attr, (void*)timerProcess, NULL) != 0)
		{
			goto Timer_out;
		}
		if (pthread_create(&gTimertask_thread_id,&thread_attr, (void*)timer_task_Process, NULL) != 0)
		{
			goto Timer_out;
		}
		
	}
	else
	{
		if (!gTimerIsRunning)
		{
			return 0;
		}
		Timer_out:
		gTimerIsRunning = 0;

		/*µÈ´ý×ÓÏß³Ì½áÊø*/
		if(gTimerBucket_thread_id)
			sem_wait(&gTimerBucketSemID);
		sem_post(&gTimerSemID);//·½±ãÔËÐÐÈÎÎñµÄ½ø³ÌÍË³ö
		if(gTimertask_thread_id)
			sem_wait(&gTimertaskSemID);
		/*ÊÍ·Å×ÊÔ´*/
		if(gTimerBucket)
			free(gTimerBucket);
		gTimerBucket = NULL;
		if(key_manger)
			free(key_manger);
		key_manger = NULL;
		pthread_mutex_destroy(&gTimerBucket_mutex);
		sem_destroy(&gTimerSemID);
		sem_destroy(&gTimerBucketSemID);
		sem_destroy(&gTimertaskSemID);

		return -1;
	}
	
	return 0;
}


