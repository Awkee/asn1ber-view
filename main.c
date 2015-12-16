/**
    测试ASN.1编码规则解析
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "asn1ber.h"

char *usage_opt[] = {
"Usage : ",
"   asn1ber [-h split_head_len] [-r skip_record_len] file ...",
"       -h 跳过文件头开始的字节数，仅执行一次",
"       -r 跳过话单头记录的长度，每次读一条话单前都执行一次",
"",
NULL
};
void
usage()
{
    char **p = usage_opt;
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
 * \param argv_idx int*     需要处理的参数索引下标
 * \return int    0:成功，其他失败
 *
 */
int GetOpt( int argc, char *argv[] , int *skip_head , int *skip_rec , int *argv_idx )
{
    int c,ret;
    ret = 0;
    *skip_head = 0;
    *skip_rec  = 0;
    while ((c = getopt (argc, argv, "h:r:")) != -1)
    {
        switch ( c )
        {
        case 'h':/*设置跳跃文件头字节数*/
            *skip_head = atoi( optarg );
            break;
        case 'r':
            *skip_rec = atoi( optarg);
            break;
        default:
            debug("Unknown option character `\\x%x'.\n",optopt);
			usage();
            exit(1);
            break;
        }
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
void print_ln( int level, int l_tag, int l_len , int offset, FILE *fp )
{
    int i ;
    if( level > 0 )
        for( i = 0; i < level ; i++)
            fprintf( fp , "\t");
    fprintf(fp,"%d,%d,%06d," , l_tag, l_len, offset);
}

/** \brief 展现BER编码指定组节点内所有节点信息(递归实现)
 *
 * \param data const void*  组节点原始二进制数据
 * \param len int   节点数据总长度字节数
 * \param offset int 文件位置偏移量
 * \param level int 递归级别(层数)
 * \param fp FILE*  结果输出文件指针(如果fp=NULL,默认输出到标准输出stdout显示)
 * \return int  0:执行成功,否则失败
 *
 */
int show_record(const void *data , int len ,int offset, int level , FILE *fp )
{
    int ret = 0;
    int is_leaf = NO;
    int pos =0,len_tag,len_len,l_tag,l_len,i;
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
        print_ln(level, l_tag, l_len, offset + pos - len_tag - len_len , fp );
        if( is_leaf == YES )
        {

            for( i = 0; i < l_len; i++)
            {
                fprintf( fp , "%02X",*(pbuff + pos + i ) );
            }
            fprintf( fp , "\n" );

            //fprintf(fp,"leaf\n");
        }
        else
        {
            fprintf( fp , "\n" );
            show_record(pbuff + pos , l_len ,offset + pos , level + 1, fp );
        }
        pos += l_len;
        //fprintf(stdout, "tag:%d,tag_len:%d,length_value:%d, length_len:%d,is_leaf:%d\n", l_tag, len_tag , l_len , len_len , is_leaf );
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
    int ret,read_len,pos, tag_len ,len, is_leaf ;
    int i,skip_head, skip_rec, argv_index,file_size,buff_size;
    len_t asn_len;
    tag_t asn_tag;
    FILE *fp;
	if( argc == 1 ){
		usage();
		exit(1);
	}
    ret = GetOpt(argc, argv, &skip_head , &skip_rec, &argv_index );
    ASSERT(ret == 0 , "Getopt error!\n");

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
                fprintf( stdout , "%d,%d,%06d\n",asn_tag, asn_len, pos - tag_len - len );
                show_record( pbuff + pos , asn_len ,pos , 1 , NULL );
                pos += asn_len;
            }
        }
        fclose( fp );
    }
    return ret;
}

