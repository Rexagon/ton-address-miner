#ifndef CELL_H
#define CELL_H

#include <stdint.h>
#include <stdbool.h>

#define HASH_SIZE 32

#define CELL_DATA_OFFSET 2

#define MAX_CONTRACT_CELLS_COUNT 6
#define HASHES_BUFFER_SIZE (MAX_CONTRACT_CELLS_COUNT * HASH_SIZE)
#define MAX_PUBLIC_KEY_CELL_DATA_SIZE 36  // label(3) + public key(32) + tag(1)

typedef struct Cell {
  uint8_t* cell_begin;
} Cell;

void cell_init(Cell* self, uint8_t* cell_begin);
uint8_t cell_get_d1(const Cell* self);
uint8_t cell_get_d2(const Cell* self);
uint8_t cell_get_data_size(const Cell* self);
uint8_t* cell_get_data(const Cell* self);
uint8_t* cell_get_refs(const Cell* self, uint8_t* refs_count);

uint16_t deserialize_cell(Cell* cell);

typedef struct SliceData {
  uint8_t* data;
  uint16_t data_window_start;
  uint16_t data_window_end;
  uint16_t data_size_bytes;
} SliceData;

void slice_data_init(SliceData* self, uint8_t* data, uint16_t data_size_bytes);
void slice_data_fill(SliceData* self, uint8_t value, uint16_t data_size_bytes);
void slice_data_truncate(SliceData* self, uint16_t size);
uint16_t slice_data_remaining_bits(const SliceData* self);
inline void slice_data_move_by(SliceData* self, uint16_t offset) {
  self->data_window_start += offset;
}
inline void slice_data_move_to(SliceData* self, uint16_t offset) {
  self->data_window_start = offset;
}
uint8_t slice_data_get_bits(const SliceData* self, uint16_t offset, uint8_t bits);
uint8_t slice_data_get_next_bit(SliceData* self);
uint64_t slice_data_get_next_int(SliceData* self, uint8_t bits);
uint64_t slice_data_get_next_size(SliceData* self, uint16_t max_value);
bool slice_data_equal(const SliceData* self, const SliceData* other);
void slice_data_append(SliceData* self, const uint8_t* data, uint16_t bits, bool append_tag);

uint32_t read_uint32be(uint8_t* buffer);

typedef struct ByteStream {
  uint16_t data_size;
  uint16_t offset;
  uint8_t* data;
} ByteStream;

void byte_stream_init(ByteStream* self, uint8_t* data, uint16_t data_size);
uint8_t* byte_stream_read_data(ByteStream* self, uint32_t data_size);
uint8_t byte_stream_read_byte(ByteStream* self);
uint32_t byte_stream_read_u32(ByteStream* self);
uint8_t* byte_stream_get_cursor(ByteStream* self);

typedef struct BocContext {
  Cell cells[MAX_CONTRACT_CELLS_COUNT];
  uint8_t hashes[HASHES_BUFFER_SIZE];
  uint8_t cell_depth[MAX_CONTRACT_CELLS_COUNT];
  uint8_t public_key_cell_data[MAX_PUBLIC_KEY_CELL_DATA_SIZE];
  uint8_t cells_count;
  uint8_t public_key_cell_index;
  uint8_t public_key_label_size_bits;
} BocContext;

typedef struct ContractContext {
  uint8_t const* code_hash;
  uint8_t const* wallet;
  uint8_t wallet_size;
  uint8_t wallet_cells_count;
  uint8_t wallet_code_child_depth;
  uint8_t wallet_data_child_depth;
} ContractContext;

void put_to_node(uint8_t cell_index, uint16_t bit_len, struct SliceData* key, BocContext* bc);

void deserialize_cells_tree(ByteStream* src, BocContext* bc, ContractContext* cc);
void find_public_key_cell(BocContext* bc);

bool calc_cell_hash(Cell* cell, uint8_t cell_index, BocContext* bc);
bool calc_root_cell_hash(Cell* cell, BocContext* bc, ContractContext* cc);

#endif
