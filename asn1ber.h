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

/** \brief ����BER��������tag�ڵ�ֵ
 *
 * \param data const void* ����ԭʼ����
 * \param tag_value unsigned int* ���tagֵ
 * \param tag_len int* tagֵռ���ֽ���
 * \param is_leaf int* ����Ƿ�Ϊԭ�ӽڵ�YES/NO
 * \param label char*   ��ʶ���ݱ�ǩ���ͣ���������ΪNULL
 * \return int 0��ʾִ�гɹ��������ʾ��������
 *
 */
int asn1ber_tag_dec(const void *data, tag_t *tag_value ,int *tag_len, int *is_leaf , char *label);

/** \brief ����BER��������length�ڵ�ֵ
 *
 * \param data const void*  ����ԭʼ����
 * \param len_value unsigned int* ������ĳ���ֵ
 * \param len int*  ���Ƚڵ�ռ���ֽ���
 * \return int
 *
 */
int asn1ber_len_dec(const void *data, len_t *len_value ,int *len);

#endif // ASN1BER_H_INCLUDED

