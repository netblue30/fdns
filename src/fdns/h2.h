#ifndef H2_H
#define H2_H
#include <stdint.h>
#define MAXBUF 2048

void h2_init(void);

// encode a header frame
// frame - http2 frame
// increment stream id (+2) before encoding
// return offset for the end of frame
uint32_t h2_encode_header(uint8_t *frame);

// decode a header frame
// frame - http2 frame
// return offset for the end of frame
uint32_t h2_decode_header(uint8_t *frame);

// encode a data frame
// frame - http2 frame
// data and length
// using the same session id as the last encoded header frame; ending the stream
// return offset for the end of the frame
uint32_t h2_encode_data(uint8_t *frame, uint8_t *data, unsigned length);

// decode a data frame
// frame - http2 frame
// offset - offset to data section in frame
// length - length of data section
// return offset for the end of the frame
uint32_t h2_decode_data(uint8_t *frame, uint32_t *offset, uint32_t *length);


#endif