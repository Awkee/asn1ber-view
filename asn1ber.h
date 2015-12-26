/*
    asn1ber  Asn.1 BER simple decode tools for C programing language.

    Copyright (C) 2015  next4nextjob(at)gmail(dot)com
    See LICENSE for licensing information

*/

#ifndef ASN1BER_H_INCLUDED
#define ASN1BER_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>

#ifndef DEBUG
    #define debug( ...)
    #define DEBUG_BER_DECODE( ...)
#else
    #define debug( ... ) fprintf( stderr, __VA_ARGS__)
    #define DEBUG_BER_DECODE( ... ) fprintf( stderr, __VA_ARGS__)
#endif

    #define ASSERT( X, Y) do {    \
    if( !(X) )                  \
    {                           \
        fprintf(stderr, "[ASSERT]:File:%s, Line:%d, Function:%s,%s\n", __FILE__, __LINE__ ,__FUNCTION__, (Y ));   \
		exit(1);				\
    }                           \
}while ( 0 )

#define YES 0
#define NO  1

typedef  unsigned int  len_t;
typedef  unsigned int  tag_t;

/** \brief 解析BER编码规则的tag节点值
 *
 * \param data const void* 输入原始数据
 * \param tag_value unsigned int* 输出tag值
 * \param tag_len int* tag值占用字节数
 * \param is_leaf int* 输出是否为原子节点YES/NO
 * \param label char*   标识数据标签类型，参数可以为NULL
 * \return int 0表示执行成功，否则表示解析错误
 *
 */
int asn1ber_tag_dec(const void *data, tag_t *tag_value ,int *tag_len, int *is_leaf , char *label);

/** \brief 解析BER编码规则的length节点值
 *
 * \param data const void*  输入原始数据
 * \param len_value unsigned int* 解析后的长度值
 * \param len int*  长度节点占用字节数
 * \return int
 *
 */
int asn1ber_len_dec(const void *data, len_t *len_value ,int *len);

#endif // ASN1BER_H_INCLUDED

