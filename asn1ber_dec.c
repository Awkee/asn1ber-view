/*
 *     asn1ber  Asn.1 BER simple decode tools for C programing language.
 *
 *     Copyright (C) 2015  next4nextjob(at)gmail(dot)com
 *     See LICENSE for licensing information
 * 
 */

/**
*   定义解析ASN.1编码规范中的BER编码规则内容

*************************************************
输出记录格式： tag,length,offset,value
示例：
69,721,000054
	0,1,000059,45
	2,3,000062,425945
	3,1,000067,00
	...
			17,3,013851,
				0,1,013853,02
		1,1,013856,00

*/

#include "asn1ber.h"

/** \brief 解析BER编码规则的tag节点值
 *  tag > 31时,
 * \param data const void* 输入原始数据
 * \param tag_value unsigned int* 输出tag值
 * \param tag_len int* tag值占用字节数
 * \param is_leaf int* 输出是否为原子节点YES/NO
 * \param label char*   标识数据标签类型，参数可以为NULL
 * \return int 0表示执行成功，否则表示解析错误
 *
 */
int asn1ber_tag_dec(const void *data, tag_t *tag_value ,int *tag_len, int *is_leaf , char *label)
{
    int ret = 0;
    const unsigned char *p_char = (unsigned char *)data;
/*
 *  get node class type
 *	label = (*p_char & 0x80 ) == 0x80 ? (*p_char & 0x40 == 0x40 ? "TYPE_11_":"TYPE_10_") : (*p_char & 0x40 == 0x40 ? "TYPE_01_":"TYPE_00_");
 */
	/* check whether the tag node's bit6 is the leaf node */
    *is_leaf = (*p_char & 0x20 ) == 0x20 ? NO:YES ;
    if( ((*p_char) & 0x1F)  == 0x1F )/*tag值大于31情况*/
    {
        *tag_value  = 0;
        DEBUG_BER_DECODE("tag_src_long:[%02X]", *p_char);
        while ( (*(++p_char)) & 0x80 )/*check if *p_char's bit8 is 1; if 1 tells not the end char */
        {
            *tag_value += ((( *p_char) & 0x7F ) << 7 );
            DEBUG_BER_DECODE("[%02X]",*p_char);
        }
		/*the end of the tag char*/
        *tag_value += *p_char;
        *tag_len = (int )(p_char - (unsigned char *)data + 1);
        DEBUG_BER_DECODE("[%02X],value:%d,tag_len:%d\n", *p_char, *tag_value, *tag_len);
    }
	else/*tag值<=31情况*/
    {
        *tag_value = (*p_char) & 0x1F;
        *tag_len = 1;
        DEBUG_BER_DECODE("tag_src_short:[%02X],value:%d,tag_len:%d\n",*p_char, *tag_value, *tag_len );
    }
    if( (*tag_value) < 0 )
        ret = -1;/*tag decode error*/
    return ret;
}

/** \brief 解析BER编码规则的length节点值
 *
 * \param data const void*  输入原始数据
 * \param len_value unsigned int* 解析后的长度值
 * \param len int*  长度节点占用字节数
 * \return int
 *
 */
int asn1ber_len_dec(const void *data, len_t *len_value ,int *len)
{
    int ret = 0,i;
    const unsigned char *p_char = (const unsigned char *)data;
    if( *p_char & 0x80 )/*长编码格式*/
    {
        *len_value = 0;
        *len = *p_char & 0x7F;/*长度值的长度*/
        DEBUG_BER_DECODE("ber_len:[%02X]",*p_char);
        for( i = 0; i < *len ; i++ )
        {
            *len_value = ((*len_value) << 8) + *(++p_char);
            DEBUG_BER_DECODE(",[%02X]",*p_char);
        }
        *len += 1;/*总长度加一个字节的首字节就是长度编码总长度*/
        DEBUG_BER_DECODE(", len:[%d],len_value:[%d]\n" , *len , *len_value );
    }
    else/*短编码格式，长度<=127*/
    {
        *len_value = *p_char ;
        *len = 1;
        DEBUG_BER_DECODE("ber_len:[%02X], len:[%d],len_value:[%d]\n", *p_char , *len , *len_value );
    }
    return ret;
}

