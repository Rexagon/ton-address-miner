#include "cell.h"

#include <stdio.h>
#include <memory.h>

#include <openssl/sha.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void cell_init(Cell* self, uint8_t* cell_begin) {
  self->cell_begin = cell_begin;
}

uint8_t cell_get_d1(const Cell* self) {
  return self->cell_begin[0];
}

uint8_t cell_get_d2(const Cell* self) {
  return self->cell_begin[1];
}

uint8_t cell_get_data_size(const Cell* self) {
  uint8_t d2 = cell_get_d2(self);
  return (d2 >> 1) + (((d2 & 1) != 0) ? 1 : 0);
}

uint8_t* cell_get_data(const Cell* self) {
  return self->cell_begin + CELL_DATA_OFFSET;
}

uint8_t* cell_get_refs(const Cell* self, uint8_t* refs_count) {
  uint8_t d1 = cell_get_d1(self);
  *refs_count = d1 & 7;
  uint8_t data_size = cell_get_data_size(self);
  return self->cell_begin + CELL_DATA_OFFSET + data_size;
}

uint16_t deserialize_cell(Cell* cell) {
  uint8_t data_size = cell_get_data_size(cell);
  uint8_t refs_count = 0;
  cell_get_refs(cell, &refs_count);

  return CELL_DATA_OFFSET + data_size + refs_count;  // cell size
}

void slice_data_init(SliceData* self, uint8_t* data, uint16_t data_size_bytes) {
  self->data = data;
  self->data_window_start = 0;
  self->data_window_end = data_size_bytes * 8;
  self->data_size_bytes = data_size_bytes;
}

void slice_data_fill(SliceData* self, uint8_t value, uint16_t data_size_bytes) {
  memset(self->data, value, data_size_bytes);
}

void slice_data_truncate(SliceData* self, uint16_t size) {
  self->data_window_end = size;
}

uint16_t slice_data_remaining_bits(const SliceData* self) {
  if (self->data_window_start > self->data_window_end) {
    return 0;
  }
  return self->data_window_end - self->data_window_start;
}

void slice_data_move_by(SliceData* self, uint16_t offset) {
  self->data_window_start += offset;
}

uint8_t slice_data_get_bits(const SliceData* self, uint16_t offset, uint8_t bits) {
  uint16_t index = self->data_window_start + offset;
  uint8_t q = index / 8;
  uint8_t r = index % 8;
  if (r == 0) {
    return self->data[q] >> (8 - r - bits);
  } else if (bits <= (8 - r)) {
    return self->data[q] >> (8 - r - bits) & ((1 << bits) - 1);
  } else {
    uint16_t ret = 0;
    if (q < self->data_size_bytes) {
      uint16_t byte = self->data[q];
      ret |= byte << 8;
    }
    if (q < self->data_size_bytes - 1) {
      ret |= self->data[q + 1];
    }

    ret = (ret >> (8 - r)) >> (8 - bits);
    return (uint8_t)ret;
  }
}

uint8_t slice_data_get_next_bit(SliceData* self) {
  uint8_t bit = slice_data_get_bits(self, 0, 1);
  slice_data_move_by(self, 1);
  return bit;
}

uint64_t slice_data_get_int(const SliceData* self, uint8_t bits) {
  if (bits == 0) {
    return 0;
  }

  uint64_t value = 0;
  uint8_t bytes = bits / 8;
  for (uint8_t i = 0; i < bytes; ++i) {
    uint64_t byte = slice_data_get_bits(self, 8 * i, 8);
    value |= byte << (8 * (7 - i));
  }

  volatile uint8_t remainder = bits % 8;
  if (remainder != 0) {
    uint64_t r = slice_data_get_bits(self, bytes * 8, remainder);
    value |= r << (8 * (7 - bytes) + (8 - remainder));
  }

  return value >> (64 - bits);
}

uint64_t SliceData_get_next_int(SliceData* self, uint8_t bits) {
  uint64_t value = slice_data_get_int(self, bits);
  slice_data_move_by(self, bits);
  return value;
}

uint8_t leading_zeros(uint16_t value) {
  uint8_t lz = 0;
  uint16_t msb = 0x8000;
  for (uint8_t i = 0; i < 16; ++i) {
    if ((value << i) & msb) {
      break;
    }
    ++lz;
  }
  return lz;
}

uint64_t slice_data_get_next_size(SliceData* self, uint16_t max_value) {
  if (max_value == 0) {
    return 0;
  }
  uint8_t bits = 16 - leading_zeros(max_value);
  uint64_t res = SliceData_get_next_int(self, bits);
  return res;
}

bool slice_data_equal(const SliceData* self, const SliceData* other) {
  uint32_t self_rb = slice_data_remaining_bits(self);
  uint32_t other_rb = slice_data_remaining_bits(other);
  if (self_rb != other_rb) {
    return false;
  }
  return slice_data_get_int(self, self_rb) == slice_data_get_int(other, other_rb);
}

void slice_data_append(SliceData* self, const uint8_t* data, uint16_t bits, bool append_tag) {
  uint8_t bytes = bits / 8;

  uint16_t offset = self->data_window_start;
  if (offset % 8 == 0 || bytes == 0) {
    memcpy(self->data + offset / 8, data, bytes ? bytes : 1);
  } else {
    uint8_t shift = offset % 8;
    uint8_t first_data_byte = offset / 8;
    uint8_t prev = 0;
    for (uint16_t i = first_data_byte, j = 0; j < bytes; ++i, ++j) {
      uint8_t cur = data[j] >> shift;
      if (j == 0) {
        uint8_t first_byte = self->data[i] >> (8 - shift);
        first_byte <<= 8 - shift;
        self->data[i] = first_byte | cur;
      } else {
        self->data[i] = prev | cur;
      }

      prev = data[j] << (8 - shift);
      if (j == bytes - 1) {
        uint8_t last_byte = prev;
        if (append_tag) {
          if (shift != 7) {
            last_byte >>= 7 - shift;
          }
          last_byte |= 1;
          if (shift != 7) {
            last_byte <<= 7 - shift;
          }

          bits += 8 - shift;
        }
        self->data[i + 1] = last_byte;
      }
    }
  }

  self->data_window_start += bits;
}

uint32_t read_uint32_be(const uint8_t* buffer) {
  return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);
}

void byte_stream_init(ByteStream* self, uint8_t* data, uint16_t data_size) {
  self->data_size = data_size;
  self->offset = 0;
  self->data = data;
}

void byte_stream_move_by(ByteStream* self, uint16_t data_size) {
  self->offset += data_size;
}

uint8_t* byte_stream_read_data(ByteStream* self, uint32_t data_size) {
  uint8_t* data = self->data + self->offset;
  byte_stream_move_by(self, data_size);
  return data;
}

uint8_t byte_stream_read_byte(ByteStream* self) {
  uint8_t byte = self->data[self->offset];
  byte_stream_move_by(self, 1);
  return byte;
}

uint32_t byte_stream_read_u32(ByteStream* self) {
  uint32_t u32 = read_uint32_be(self->data + self->offset);
  byte_stream_move_by(self, sizeof(uint32_t));
  return u32;
}

uint8_t* byte_stream_get_cursor(ByteStream* self) {
  return self->data + self->offset;
}

uint8_t get_label(uint8_t max, SliceData* slice, SliceData* label) {
  slice_data_get_next_bit(slice);  // label short
  slice_data_get_next_bit(slice);  // label long
  uint8_t value = slice_data_get_next_bit(slice) ? 0xff : 0;
  uint8_t length = slice_data_get_next_size(slice, max);

  uint8_t length_bytes = length / 8 + (length % 8 ? 1 : 0);
  slice_data_fill(label, value, length_bytes);
  slice_data_truncate(label, length);
  return length >= max ? 0 : (max - length);
}

void put_to_node(uint8_t cell_index, uint16_t bit_len, SliceData* key, BocContext* bc) {
  static const uint8_t key_len_bytes = 8;

  Cell* cell = &bc->cells[cell_index];
  SliceData slice;
  slice_data_init(&slice, cell_get_data(cell), cell_get_data_size(cell));

  SliceData label;
  uint8_t label_data[8];
  memset(label_data, 0, sizeof(label_data));
  slice_data_init(&label, label_data, sizeof(label_data));
  get_label(bit_len, &slice, &label);

  if (slice_data_equal(&label, key)) {
    uint8_t len = 16 - leading_zeros(bit_len);
    uint8_t label_size_bits = 2 + 1 + len;  // prefix + key bit + len
    bc->public_key_label_size_bits = label_size_bits;
    bc->public_key_cell_index = cell_index;
    return;
  }

  // common prefix
  {
    uint8_t max_prefix_len = MIN(slice_data_remaining_bits(&label), slice_data_remaining_bits(key));
    uint8_t i = 0;
    while (i < max_prefix_len && slice_data_get_bits(&label, i, 1) == slice_data_get_bits(key, i, 1)) {
      i += 1;
    }

    slice_data_move_by(key, i);
    slice_data_truncate(&label, i);
    uint8_t label_rb = slice_data_remaining_bits(&label);
    bit_len -= label_rb;
  }

  uint8_t next_index = slice_data_get_next_bit(key);

  uint8_t refs_count = 0;
  uint8_t* refs = cell_get_refs(&bc->cells[cell_index], &refs_count);
  uint8_t next_cell = refs[next_index];
  bit_len -= 1;

  return put_to_node(next_cell, bit_len, key, bc);
}

void deserialize_cells_tree(ByteStream* src, BocContext* bc, ContractContext* cc) {
  byte_stream_read_u32(src);  // magic

  uint8_t ref_size = byte_stream_read_byte(src) & 0x7;  // size in bytes

  uint8_t offset_size = byte_stream_read_byte(src);

  byte_stream_read_byte(src);  // shift cells count
  uint8_t cells_count = cc->wallet_cells_count;

  uint8_t roots_count = byte_stream_read_byte(src);
  bc->cells_count = cells_count;

  byte_stream_read_byte(src);               // absent count
  byte_stream_read_data(src, offset_size);  // total cells size
  byte_stream_read_data(src, roots_count * ref_size);

  Cell cell;
  for (uint8_t i = 0; i < cells_count; ++i) {
    uint8_t* cell_begin = byte_stream_get_cursor(src);
    cell_init(&cell, cell_begin);
    uint16_t offset = deserialize_cell(&cell);
    bc->cells[i] = cell;
    byte_stream_read_data(src, offset);
  }
}

void find_public_key_cell(BocContext* bc) {
  uint8_t refs_count = 0;
  uint8_t* refs = cell_get_refs(&bc->cells[0], &refs_count);

  uint8_t data_root = refs[refs_count - 1];
  refs = cell_get_refs(&bc->cells[data_root], &refs_count);

  uint8_t key_buffer[8];
  SliceData key;
  memset(key_buffer, 0, sizeof(key_buffer));
  slice_data_init(&key, key_buffer, sizeof(key_buffer));

  uint16_t bit_len = slice_data_remaining_bits(&key);
  put_to_node(refs[0], bit_len, &key, bc);
}

bool calc_cell_hash(Cell* cell, const uint8_t cell_index, BocContext* bc) {
  uint8_t hash_buffer[262];  // d1(1) + d2(1) + data(128) + 4 * (depth(1) + hash(32))

  uint16_t hash_buffer_offset = 0;
  hash_buffer[0] = cell_get_d1(cell);
  hash_buffer[1] = cell_get_d2(cell);
  hash_buffer_offset += 2;
  uint8_t data_size = cell_get_data_size(cell);

  if (bc->public_key_cell_index && cell_index == bc->public_key_cell_index) {
    memcpy(hash_buffer + hash_buffer_offset, bc->public_key_cell_data, data_size);
  } else {
    memcpy(hash_buffer + hash_buffer_offset, cell_get_data(cell), data_size);
  }
  hash_buffer_offset += data_size;

  uint8_t refs_count = 0;
  uint8_t* refs = cell_get_refs(cell, &refs_count);

  for (uint8_t child = 0; child < refs_count; ++child) {
    uint8_t* depth = &bc->cell_depth[cell_index];
    uint8_t child_depth = bc->cell_depth[refs[child]];
    *depth = (*depth > child_depth + 1) ? *depth : (child_depth + 1);
    uint8_t buf[2];
    buf[0] = 0;
    buf[1] = child_depth;
    memcpy(hash_buffer + hash_buffer_offset, buf, sizeof(buf));
    hash_buffer_offset += sizeof(buf);
  }

  for (uint8_t child = 0; child < refs_count; ++child) {
    uint8_t* cell_hash = bc->hashes + refs[child] * HASH_SIZE;
    memcpy(hash_buffer + hash_buffer_offset, cell_hash, HASH_SIZE);
    hash_buffer_offset += HASH_SIZE;
  }

  uint8_t* result = bc->hashes + cell_index * HASH_SIZE;
  return SHA256(hash_buffer, hash_buffer_offset, result) == result;
}

bool calc_root_cell_hash(Cell* cell, BocContext* bc, ContractContext* cc) {
  uint8_t hash_buffer[262];  // d1(1) + d2(1) + data(128) + 4 * (depth(1) + hash(32))

  uint16_t hash_buffer_offset = 0;
  hash_buffer[0] = cell_get_d1(cell);
  hash_buffer[1] = cell_get_d2(cell);
  hash_buffer_offset += 2;

  uint8_t data_size = cell_get_data_size(cell);
  memcpy(hash_buffer + hash_buffer_offset, cell_get_data(cell), data_size);
  hash_buffer_offset += data_size;

  // code hash child depth
  hash_buffer[hash_buffer_offset] = 0x00;
  hash_buffer[hash_buffer_offset + 1] = cc->wallet_code_child_depth;
  hash_buffer_offset += 2;

  // data hash child depth
  hash_buffer[hash_buffer_offset] = 0x00;
  hash_buffer[hash_buffer_offset + 1] = cc->wallet_data_child_depth;
  hash_buffer_offset += 2;

  // append code hash
  memcpy(hash_buffer + hash_buffer_offset, cc->code_hash, HASH_SIZE);
  hash_buffer_offset += HASH_SIZE;

  // append data hash
  memcpy(hash_buffer + hash_buffer_offset, bc->hashes + HASH_SIZE, HASH_SIZE);
  hash_buffer_offset += HASH_SIZE;

  uint8_t* result = bc->hashes;
  return SHA256(hash_buffer, hash_buffer_offset, result) == result;
}
