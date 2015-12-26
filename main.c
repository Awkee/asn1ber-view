/*
    asn1ber  Asn.1 BER simple decode tools for C programing language.

    Copyright (C) 2015  next4nextjob(at)gmail(dot)com
    See LICENSE for licensing information

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "asn1ber.h"

/*
 * 缓存解析一个节点内容的所有信息
 */
char tree_buf[ 1024 * 8 ] ; 
#define USAGE_STR       "   asn1ber [-h split_head_len] [-r skip_record_len] [-t grep_tag -g grep_string] file ..."

char *usage_opt_en[] = {
        "Usage : ",
        USAGE_STR,
        "       -h skip file fixed header n bytes",
        "       -r skip record fixed header m bytes",
        "       -t the tag node tree you want to grep",
		"       -g the text value you want to grep",
        "",
        NULL
};

char *usage_opt_zh[] = {
        "命令介绍:",
        USAGE_STR,
        "       -h 跳过文件头开始的字节数，仅执行一次",
        "       -r 跳过话单头记录的长度，每次读一条话单前都执行一次",
        "		-t 想要查找的tag节点树",
        "		-g 想要查找的文本信息,需要跟-t参数一起使用",
        "",
        NULL
};
void
usage()
{
    char **p = usage_opt_en;
    while( *p != NULL ){
        fprintf(stdout,"%s\n",*p++);
	}
}

/** \brief 传入参数解析模块
 *
 * \param argc int          参数数
 * \param argv[] char*      参数值数组表
 * \param skip_head int*    输出跳过的文件头部字节数
 * \param skip_rec int*     输出每次读取根节点前需要跳过的字节数
 * \param grep_tag int*		需要查找的tag节点树
 * \param grep_value char*	查找匹配的字符串信息
 * \param argv_idx int*     需要处理的参数索引下标
 * \return int    0:成功，其他失败
 *
 */
int get_opt( int argc, char *argv[] , int *skip_head , int *skip_rec , int *grep_tag, char *grep_value , int *argv_idx )
{
    int c,ret;
    ret = 0;
    *skip_head = 0;
    *skip_rec  = 0;
    while ((c = getopt (argc, argv, "h:r:t:g:")) != -1)
    {
        switch ( c )
        {
        case 'h':/*设置跳跃文件头字节数*/
            *skip_head = atoi( optarg );
            break;
        case 'r':
            *skip_rec = atoi( optarg);
            break;
        case 't':
            *grep_tag = atoi( optarg);/*grep the *grep_tag node's value info */
			debug("grep_tag:%d\n",*grep_tag);
            break;
        case 'g':
			memset( grep_value, 0, sizeof(grep_value) );
            strcpy(grep_value ,optarg);/* grep value string */
			debug("grep_value:%s\n", grep_value);
            break;

        default:
            debug("Unknown option character `\\x%x'.\n",optopt);
			usage();
            exit(1);
            break;
        }
    }
	if ( ( *grep_tag > 0 && grep_value[0] == 0 ) 
		|| ( grep_value[0] != 0 && (*grep_tag) == 0 ) 
	   )
	{
		fprintf(stderr, "the -t and -g param should be set in the command!\n");
		ret = -1;
	}
    *argv_idx = optind;
    return ret;
}

/** \brief 获取path指定的文件大小字节数
 *
 * \param path const char*  文件路径
 * \return unsigned long    返回文件大小字节数，-1表示执行失败
 *
 */
unsigned long get_file_size(const char *path)
{
    unsigned long filesize = 0;
    struct stat statbuff;
    if(stat(path, &statbuff) < 0){
        return filesize;
    }else{
        filesize = statbuff.st_size;
    }
    return filesize;
}

/** \brief 打印单行的tag,len值
 *
 * \param level int 输出级别(层数)
 * \param l_tag int 需要输出的tag值
 * \param l_len int 需要输出的value的字节数
 * \param offset int 需要输出的文件位置偏移量
 * \param fp FILE*  输出文件指针
 * \return void
 *
 */
void print_ln( int level, int l_tag, int l_len , int offset, char *rec_buf )
{
    int i ;
	char *p_rec_buf = rec_buf;
    if( level > 0 )
        for( i = 0; i < level ; i++)
            sprintf( p_rec_buf ++ , "\t");
    sprintf(p_rec_buf ,"%d,%d,%06d," , l_tag, l_len, offset);
	debug("current_buf:[%s]\n", rec_buf);
	p_rec_buf = rec_buf + strlen( p_rec_buf);
}

/** \brief 展现BER编码指定组节点内所有节点信息(递归实现)
 *
 * \param data const void*  组节点原始二进制数据
 * \param len int   节点数据总长度字节数
 * \param offset int 文件位置偏移量
 * \param level int 递归级别(层数)
 * \param fp FILE*  结果输出文件指针(如果fp=NULL,默认输出到标准输出stdout显示)
 * \param rec_buf char* 存储记录解析结果
 * \return int  0:执行成功,否则失败
 *
 */
int show_record(const void *data , int len ,int offset, int level , FILE *fp , char *rec_buf )
{
    int ret = 0;
    int is_leaf = NO;
    int pos =0,len_tag,len_len,l_tag,l_len,i;
	char *p_rec_buf = rec_buf;
    const unsigned char *pbuff = data;
    if( fp == NULL)
    {
        fp = stdout;
    }
    while( pos < len )
    {
        asn1ber_tag_dec(pbuff + pos, (tag_t *)&l_tag , &len_tag , &is_leaf , NULL );
        pos += len_tag;
        asn1ber_len_dec(pbuff + pos  , (len_t *)&l_len , &len_len );
        pos += len_len ;
        print_ln(level, l_tag, l_len, offset + pos - len_tag - len_len , p_rec_buf );
		p_rec_buf = rec_buf + strlen( rec_buf );
        if( is_leaf == YES )
        {
            for( i = 0; i < l_len; i++)
            {
				sprintf( p_rec_buf , "%02X" , *(pbuff + pos + i ) );
				p_rec_buf += 2;
            }
			strcpy(p_rec_buf , "\n");
			p_rec_buf ++;
        }
        else
        {
            strcpy(p_rec_buf , "\n");
			p_rec_buf ++;
            show_record(pbuff + pos , l_len ,offset + pos , level + 1, fp , p_rec_buf );
			p_rec_buf = rec_buf + strlen( rec_buf );
        }
        pos += l_len;
    }
    return ret;
}

int main(int argc , char *argv[] )
{
    /**
    *   TODO: 添加head信息和跳过循环定长信息
    *       定长头部:一次跳过
    *       循环定长:循环跳过
    */
    unsigned char *pbuff;
	char grep_value[1024];
    int ret,read_len,pos, tag_len ,len, is_leaf ;
    int i, grep_tag ,skip_head, skip_rec, argv_index,file_size,buff_size;
    len_t asn_len;
    tag_t asn_tag;
    FILE *fp;
	if( argc == 1 ){
		usage();
		exit(1);
	}
	skip_head = skip_rec = grep_tag = 0;
	memset( grep_value, 0, sizeof(grep_value) );
    ret = get_opt(argc, argv, &skip_head , &skip_rec, &grep_tag , grep_value , &argv_index );
    ASSERT(ret == 0 , "get_opt error!\n");

    buff_size = 0;
    pbuff  = NULL;
    for( i = argv_index ; i < argc ; i++ )
    {
        file_size = get_file_size( argv[i] );
        ASSERT(file_size > 0 , "get_file_size error!\n");
        if( pbuff == NULL )
        {
            pbuff = (unsigned char *)malloc( file_size );
            buff_size = file_size;
        }
        else if ( buff_size < file_size )
        {
            free(pbuff);
            pbuff = (unsigned char *)malloc( file_size );
            buff_size = file_size;
        }
        memset(pbuff,0,buff_size);

        debug("begin to read file[%s]\n", argv[i]);
        fp = fopen( argv[i],"rb" );
        ASSERT( fp != NULL, "open file error!\n");
        read_len = fread( pbuff, 1,file_size, fp ) ;
        if( read_len == file_size )
        {
            len = 0;
            asn_len = 0;
            pos = 0;
            if( skip_head > 0 )
                pos += skip_head;
            while ( pos  < read_len )
            {
                if( skip_rec > 0 )
                    pos += skip_rec;
				ret = asn1ber_tag_dec(pbuff + pos, &asn_tag , &tag_len , &is_leaf , NULL );
				pos += tag_len;
				ret = asn1ber_len_dec(pbuff + pos  , &asn_len , &len );
				pos += len;
				sprintf( tree_buf , "%d,%d,%06d\n",asn_tag, asn_len, pos - tag_len - len );
                show_record( pbuff + pos , asn_len , pos , 1 , NULL , tree_buf + strlen(tree_buf) );
				if( grep_tag == asn_tag )
				{
					if( strstr( tree_buf, grep_value ) )
					{
						fprintf( stdout, "%s\n" , tree_buf );
					}
				}
				else
                pos += asn_len;
            }
        }
        fclose( fp );
    }
    return ret;
}

