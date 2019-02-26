#include <string.h>
#include "mible_type.h"
#include "queue.h"

#define IS_POWER_OF_TWO(A) ( ((A) != 0) && ((((A) - 1) & (A)) == 0) )

mible_status_t queue_init(queue_t *q, void *buf, char queue_size, char elem_size)
{
    if (buf == NULL || q == NULL)
        return MI_ERR_INVALID_PARAM;

    if (!IS_POWER_OF_TWO(queue_size))
        return MI_ERR_DATA_SIZE;

    q->buf = buf;
    q->mask = queue_size - 1;
    q->elem_size = elem_size;
    q->rd_ptr = 0;
    q->wr_ptr = 0;

    return MI_SUCCESS;
}

mible_status_t enqueue(queue_t *q, void *in)
{
    if (((q->wr_ptr - q->rd_ptr) & q->mask) == q->mask) {
        return MI_ERR_NO_MEM;
    }
    
    /* q->buf[q->wr_ptr++] = in; */
    memcpy((char*)q->buf + q->wr_ptr * q->elem_size, in, q->elem_size);
    q->wr_ptr++;
    q->wr_ptr &= q->mask;
    
    return MI_SUCCESS;
}

mible_status_t dequeue(queue_t *q, void *out)
{
    if (((q->wr_ptr - q->rd_ptr) & q->mask) > 0) {
        /* *out = q->buf[q->rd_ptr++]; */
        memcpy(out, (char*)q->buf + q->rd_ptr * q->elem_size, q->elem_size);
        q->rd_ptr++;
        q->rd_ptr &= q->mask;
        return MI_SUCCESS;
    } else
        return MI_ERR_NOT_FOUND;
}
