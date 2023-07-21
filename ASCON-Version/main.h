#pragma once
/**
 * @brief 第一层协议入口（网关 <--> 域控制器）
 */
void layerOne();

/**
 * @brief 第二层协议入口（域控制器 <--> 域内ECU）
 *		  
 */
void layerTwo();

void asconTest();