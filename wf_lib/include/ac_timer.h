/*
  $Id: ac_timer.h,v 1.1 2014/07/22 02:08:13 xiaolj Exp $
  $Author: xiaolj $
  $Date: 2014/07/22 02:08:13 $
  $Log: ac_timer.h,v $
  Revision 1.1  2014/07/22 02:08:13  xiaolj
  first

*/
#ifndef __SHIYAN_TIMER__
#define  __SHIYAN_TIMER__

#define MAX_TIMER_SIZE          1024               /*最大用户(定时器)数量*/

/********************************************************************************
 * 功能     : 增加一个定时器，到期时执行callBack函数
 *    
 * 参数     : 
 * [IN] 
 *   second - 定时时间
 *   callBack - 定时事件处理函数
 * [OUT]
 *   无
 * 
 * 返回值   : 
 *   0  - 错误
 *   非0 - timer的句柄，用户关闭时使用
*******************************************************************************/  
extern int timerAdd(int second,int (*callBack)(void*,int), void *user_data,int len,int if_reop);
extern void timerStop(int key);

/********************************************************************************
 * 功能     : 停止定功能开启关闭函数
 *    
 * 参数     : 
 * [IN] 
 *   isStart - 1，开启；0，关闭
 *
 * [OUT]
 *   无
 * 
 * 返回值   : 
 *   OK       -   处理成功
 *   ERROR    -   处理失败
*******************************************************************************/  
extern int timerTaskStart(int isStart);

#endif
