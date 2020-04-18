// MIT License
//
// Copyright (c) 2020 Victor Gomes
// Copyright (c) 2015 Robert Nystrom (http://craftinginterpreters.com/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DECLARE(name) \
  struct name;        \
  typedef struct name name

#define UNUSED __attribute__((unused))

// #define DEBUG_PRINT_CODE
// #define DEBUG_TRACE_EXECUTION
// #define DEBUG_STRESS_GC
// #define DEBUG_LOG_GC

// Constants

#define FRAMES_MAX 64
#define STACK_MAX (FRAMES_MAX * (UINT8_MAX + 1))
#define TABLE_MAX_LOAD 0.75
#define GC_HEAP_GROW_FACTOR 2

// Runtime objects and values.
DECLARE(Class);
DECLARE(Closure);
DECLARE(Function);
DECLARE(Instance);
DECLARE(Method);
DECLARE(Native);
DECLARE(Object);
DECLARE(String);
DECLARE(Upvalue);
DECLARE(Value);
DECLARE(ValueArray);

// Hashtable.
DECLARE(Entry);
DECLARE(Table);

// VM
DECLARE(Chunk);
DECLARE(VM);

struct Table {
  int count;  // Includes tombstones.
  int capacity;
  Entry *entries;
};

struct ValueArray {
  int count;
  int capacity;
  Value *values;
};

struct Chunk {
  int count;
  int capacity;
  uint8_t *code;
  int *lines;
  ValueArray constants;
};

typedef Value (*NativeFn)(int arg_count, Value *args);

typedef enum {
  VAL_BOOL,
  VAL_NIL,
  VAL_NUMBER,
  VAL_OBJECT,
} ValueType;

typedef enum {
  OBJ_CLASS,
  OBJ_CLOSURE,
  OBJ_FUNCTION,
  OBJ_INSTANCE,
  OBJ_METHOD,
  OBJ_NATIVE,
  OBJ_STRING,
  OBJ_UPVALUE
} ObjectType;

typedef enum {
  TYPE_FUNCTION,
  TYPE_METHOD,
  TYPE_INIT,
  TYPE_SCRIPT,
} FunctionType;

struct Object {
  ObjectType type;
  bool is_marked;
  Object *next;
};

struct String {
  Object obj;
  int length;
  const char *chars;
  uint32_t hash;
};

struct Value {
  ValueType type;
  union {
    bool boolean;
    double number;
    Object *object;
  } as;
};

struct Function {
  Object obj;
  int arity;
  int upvalue_count;
  Chunk chunk;
  String *name;
};

struct Upvalue {
  Object obj;
  Value *location;
  Value closed;
  Upvalue *next;
};

struct Closure {
  Object obj;
  Function *function;
  Upvalue **upvalues;
  int upvalue_count;
};

struct Class {
  Object obj;
  String *name;
  Table methods;
};

struct Instance {
  Object obj;
  Class *class;
  Table fields;
};

struct Method {
  Object obj;
  Value receiver;
  Closure *method;
};

struct Native {
  Object obj;
  NativeFn function;
};

typedef enum {
  INTERPRET_OK,
  INTERPRET_COMPILE_ERROR,
  INTERPRET_RUNTIME_ERROR,
} InterpretResult;

typedef enum {
  // Single-character tokens.
  TK_LPAREN,
  TK_RPAREN,
  TK_LBRACE,
  TK_RBRACE,
  TK_COMMA,
  TK_DOT,
  TK_MINUS,
  TK_PLUS,
  TK_SEMI,
  TK_SLASH,
  TK_STAR,
  // One or two character tokens.
  TK_BANG,
  TK_BANG_EQUAL,
  TK_EQUAL,
  TK_EQUAL_EQUAL,
  TK_GREATER,
  TK_GREATER_EQUAL,
  TK_LESS,
  TK_LESS_EQUAL,
  // Literals.
  TK_ID,
  TK_STRING,
  TK_NUMBER,
  // Keywords.
  TK_AND,
  TK_CLASS,
  TK_ELSE,
  TK_FALSE,
  TK_FOR,
  TK_FUN,
  TK_IF,
  TK_NIL,
  TK_OR,
  TK_PRINT,
  TK_RETURN,
  TK_SUPER,
  TK_THIS,
  TK_TRUE,
  TK_VAR,
  TK_WHILE,
  // Misc.
  TK_ERROR,
  TK_EOF
} TokenType;

typedef struct {
  TokenType type;
  const char *start;
  int length;
  int line;
} Token;

typedef enum {
  // Literals
  OP_CONST,
  OP_NIL,
  OP_TRUE,
  OP_FALSE,
  // Getters/Setters
  OP_SET_LOCAL,
  OP_GET_LOCAL,
  OP_SET_GLOBAL,
  OP_GET_GLOBAL,
  OP_GET_PROP,
  OP_SET_PROP,
  OP_GET_SUPER,
  OP_SET_UPVALUE,
  OP_GET_UPVALUE,
  // Arithmetic operations
  OP_NEG,
  OP_ADD,
  OP_SUB,
  OP_MUL,
  OP_DIV,
  // Comparisons
  OP_NOT,
  OP_EQUAL,
  OP_GREATER,
  OP_LESS,
  // Jumps
  OP_JMP,
  OP_JMP_IF_FALSE,
  OP_LOOP,
  OP_CALL,
  // Fast calls (Invokes)
  OP_SUPER_INVOKE,  // OP_GET_SUPER + OP_CALL
  OP_INVOKE,        // OP_GET_PROPERTY + OP_CALL
  // Closures
  OP_CLOSURE,
  OP_CLOSE_UPVALUE,
  // Class
  OP_CLASS,
  OP_INHERIT,
  OP_METHOD,
  // Misc
  OP_DEFINE_GLOBAL,
  OP_POP,
  OP_PRINT,
  OP_RET,
  OP_CODE_SIZE
} OpCode;
static_assert(OP_CODE_SIZE < 256, "Maximum number of possible bytecodes.");

// Object constructors
#define BOOL(value) ((Value){VAL_BOOL, {.boolean = value}})
#define NIL ((Value){VAL_NIL, {.number = 0}})
#define NUMBER(value) ((Value){VAL_NUMBER, {.number = value}})
#define OBJECT(value) ((Value){VAL_OBJECT, {.object = (Object *)value}})

// Object casting
#define AS_OBJECT(value) ((value).as.object)
#define AS_CLASS(value) ((Class *)AS_OBJECT(value))
#define AS_INSTANCE(value) ((Instance *)AS_OBJECT(value))
#define AS_METHOD(value) ((Method *)AS_OBJECT(value))
#define AS_CLOSURE(value) ((Closure *)AS_OBJECT(value))
#define AS_FUNCTION(value) ((Function *)AS_OBJECT(value))
#define AS_NATIVE(value) ((Native *)AS_OBJECT(value))->function
#define AS_STRING(value) ((String *)AS_OBJECT(value))

// Check value types
#define IS_BOOL(value) ((value).type == VAL_BOOL)
#define IS_NIL(value) ((value).type == VAL_NIL)
#define IS_NUMBER(value) ((value).type == VAL_NUMBER)
#define IS_OBJECT(value) ((value).type == VAL_OBJECT)
#define IS_CLASS(value) (object_is_type(value, OBJ_CLASS))
#define IS_INSTANCE(value) (object_is_type(value, OBJ_INSTANCE))
#define IS_METHOD(value) (object_is_type(value, OBJ_METHOD);
#define IS_CLOSURE(value) (object_is_type(value, OBJ_CLOSURE))
#define IS_FUNCTION(value) (object_is_type(value, OBJ_FUNCTION))
#define IS_NATIVE(value) (object_is_type(value, OBJ_NATIVE))
#define IS_STRING(value) (object_is_type(value, OBJ_STRING))

// Memory
#define ALLOCATE(type, count) \
  (type *)reallocate(NULL, 0, sizeof(type) * (count))
#define FREE(type, pointer) reallocate(pointer, sizeof(type), 0)
static void *reallocate(void *prev, size_t old_size, size_t new_size);

// Array
#define ARRAY_GROW(prev, type, old_count, count) \
  (type *)reallocate(prev, sizeof(type) * (old_count), sizeof(type) * (count))
#define ARRAY_FREE(type, pointer, old_count) \
  reallocate(pointer, sizeof(type) * (old_count), 0)
static inline int array_grow_capacity(int capacity);

// Runtime objects
static Object *object_allocate(size_t size, ObjectType type);
#define OBJECT_ALLOCATE(type, obj_type) \
  (type *)object_allocate(sizeof(type), obj_type)
static void object_free(Object *object);
static void object_mark(Object *object);

// Object constructors
static Class *class_new(String *name);
static Closure *closure_new(Function *function);
static Function *function_new();
static Instance *instance_new(Class *class);
static Method *method_new(Value receiver, Closure *method);
static Native *native_new(NativeFn function);
static Upvalue *upvalue_new(Value *slot);

// String
static String *string_take(const char *chars, int length);
static String *string_copy(const char *chars, int length);

// Value
static bool value_equals(Value a, Value b);
static void value_print(Value value);
static void value_mark(Value value);

// Array of Values
static void value_array_init(ValueArray *array);
static void value_array_free(ValueArray *array);
static void value_array_write(ValueArray *array, Value value);

// HashTable of Values
static void table_init(Table *table);
static void table_free(Table *table);
static bool table_get(Table *table, String *key, Value *value);
static bool table_set(Table *table, String *key, Value value);
static bool table_delete(Table *table, String *key);
static void table_add_all(Table *from, Table *to);
static String *table_find_string(Table *table, const char *chars, int length,
                                 uint32_t hash);
static void table_mark(Table *table);

// Chunk of instructions
static void chunk_init(Chunk *chunk);
static void chunk_free(Chunk *chunk);
static void chunk_write(Chunk *chunk, uint8_t byte, int line);
static int chunk_add_constant(Chunk *chunk, Value value);

// Disassembly
UNUSED static void disassemble_chunk(Chunk *chunk, const char *name);
static int disassemble_instruction(Chunk *chunk, int offset);

// Scanner
static void scanner_init(const char *source);
static Token scan_token();

// Parser
static void parser_error(const char *message);
static void parse();

// Emitter
static void emit_byte(uint8_t byte);
static void emit_bytes(uint8_t byte1, uint8_t byte2);
static void emit_constant(Value value);
static void emit_define_variable(uint8_t global);
static int emit_jump(uint8_t instruction);
static void emit_patch_jump(int offset);
static void emit_loop(int loop_start);
static void emit_return();

// Scope
static void scope_begin();
static void scope_end();
static int scope_depth();
static void scope_add_local(Token name);
static bool scope_is_declared(Token *name);
static int scope_resolve_local(Token *name);
static int scope_resolve_upvalue(Token *name);
static void scope_mark_initialized();
static bool scope_identifiers_equal(Token *a, Token *b);

// Compiler
static Chunk *current_chunk();
static bool compiler_is_script();
static bool compiler_is_init();
static uint8_t compiler_make_constant(Value value);
static void compile_function(FunctionType type);
static Function *compile(const char *source);
static void compiler_mark_roots();

// VM
static void vm_init();
static void vm_free();
static void vm_push(Value value);
static Value vm_pop();
static InterpretResult vm_interpret(const char *source);
static void vm_add_object(Object *object);
static void vm_add_internal_string(String *string);
static String *vm_get_internal_string(const char *chars, int length,
                                      uint32_t hash);
static void vm_define_native(const char *name, NativeFn function);

// GC
static void gc_init();
static void gc();

// Native functions
static Value native_clock(int arg_count, Value *args);

//=======================================================================//
// Array
//=======================================================================//

static inline int array_grow_capacity(int capacity) {
  return capacity < 8 ? 8 : 2 * capacity;
}

//=======================================================================//
// Object
//=======================================================================//

static Object *object_allocate(size_t size, ObjectType type) {
  Object *object = (Object *)reallocate(NULL, 0, size);
  object->type = type;
  vm_add_object(object);
#ifdef DEBUG_LOG_GC
  printf("%p allocate %ld for %d\n", (void *)object, size, type);
#endif
  return object;
}

static void object_free(Object *object) {
#ifdef DEBUG_LOG_GC
  printf("%p free type %d\n", (void *)object, object->type);
#endif
  switch (object->type) {
    case OBJ_CLASS: {
      Class *class = (Class *)object;
      table_free(&class->methods);
      FREE(Class, object);
      break;
    }
    case OBJ_CLOSURE: {
      Closure *closure = (Closure *)object;
      ARRAY_FREE(Upvalue *, closure->upvalues, closure->upvalue_count);
      FREE(Closure, object);
      break;
    }
    case OBJ_FUNCTION: {
      Function *function = (Function *)object;
      chunk_free(&function->chunk);
      FREE(Function, object);
      break;
    }
    case OBJ_INSTANCE: {
      Instance *instance = (Instance *)object;
      table_free(&instance->fields);
      FREE(Instance, object);
      break;
    }
    case OBJ_METHOD:
      FREE(Method, object);
      break;
    case OBJ_NATIVE:
      FREE(Native, object);
      break;
    case OBJ_STRING: {
      String *string = (String *)object;
      ARRAY_FREE(char, (char *)string->chars, string->length + 1);
      FREE(String, object);
      break;
    }
    case OBJ_UPVALUE:
      FREE(Upvalue, object);
      break;
  }
}

static inline bool object_is_type(Value value, ObjectType type) {
  return IS_OBJECT(value) && AS_OBJECT(value)->type == type;
}

static void function_print(Function *function) {
  if (function->name == NULL) {
    printf("<script>");
    return;
  }
  printf("<fn %s>", function->name->chars);
}

static void object_print(Value value) {
  switch (AS_OBJECT(value)->type) {
    case OBJ_CLASS:
      printf("%s", AS_CLASS(value)->name->chars);
      break;
    case OBJ_CLOSURE:
      function_print(AS_CLOSURE(value)->function);
      break;
    case OBJ_FUNCTION:
      function_print(AS_FUNCTION(value));
      break;
    case OBJ_INSTANCE:
      printf("%s instance", AS_INSTANCE(value)->class->name->chars);
      break;
    case OBJ_METHOD:
      function_print(AS_METHOD(value)->method->function);
      break;
    case OBJ_NATIVE:
      printf("<native fn>");
      break;
    case OBJ_STRING:
      printf("%s", (AS_STRING(value))->chars);
      break;
    case OBJ_UPVALUE:
      printf("upvalue");
      break;
  }
}

//=======================================================================//
// Object constructors
//=======================================================================//

static Class *class_new(String *name) {
  Class *class = OBJECT_ALLOCATE(Class, OBJ_CLASS);
  class->name = name;
  table_init(&class->methods);
  return class;
}

static Closure *closure_new(Function *function) {
  Upvalue **upvalues = ALLOCATE(Upvalue *, function->upvalue_count);
  for (int i = 0; i < function->upvalue_count; i++) {
    upvalues[i] = NULL;
  }
  Closure *closure = OBJECT_ALLOCATE(Closure, OBJ_CLOSURE);
  closure->function = function;
  closure->upvalues = upvalues;
  closure->upvalue_count = function->upvalue_count;
  return closure;
}

static Function *function_new() {
  Function *function = OBJECT_ALLOCATE(Function, OBJ_FUNCTION);
  function->arity = 0;
  function->upvalue_count = 0;
  function->name = NULL;
  chunk_init(&function->chunk);
  return function;
}

static Instance *instance_new(Class *class) {
  Instance *instance = OBJECT_ALLOCATE(Instance, OBJ_INSTANCE);
  instance->class = class;
  table_init(&instance->fields);
  return instance;
}

static Method *method_new(Value receiver, Closure *method) {
  Method *bound = OBJECT_ALLOCATE(Method, OBJ_METHOD);
  bound->receiver = receiver;
  bound->method = method;
  return bound;
}

static Native *native_new(NativeFn function) {
  Native *native = OBJECT_ALLOCATE(Native, OBJ_NATIVE);
  native->function = function;
  return native;
}

static Upvalue *upvalue_new(Value *slot) {
  Upvalue *upvalue = OBJECT_ALLOCATE(Upvalue, OBJ_UPVALUE);
  upvalue->closed = NIL;
  upvalue->location = slot;
  upvalue->next = NULL;
  return upvalue;
}

//=======================================================================//
// String
//=======================================================================//

//  FNV-1a
static uint32_t string_hash(const char *key, int length) {
  uint32_t hash = 2166136261u;
  for (int i = 0; i < length; i++) {
    hash ^= key[i];
    hash *= 16777619;
  }
  return hash;
}

static String *string_allocate(const char *chars, int length, uint32_t hash) {
  String *str = OBJECT_ALLOCATE(String, OBJ_STRING);
  str->length = length;
  str->chars = chars;
  str->hash = hash;
  vm_add_internal_string(str);
  return str;
}

static String *string_take(const char *chars, int length) {
  uint32_t hash = string_hash(chars, length);
  String *interned = vm_get_internal_string(chars, length, hash);
  if (interned != NULL) {
    ARRAY_FREE(char, (char *)chars, length + 1);
    return interned;
  }

  return string_allocate(chars, length, hash);
}

static String *string_copy(const char *chars, int length) {
  uint32_t hash = string_hash(chars, length);
  String *interned = vm_get_internal_string(chars, length, hash);
  if (interned != NULL) return interned;

  char *heap_chars = ALLOCATE(char, length + 1);
  memcpy(heap_chars, chars, length);
  heap_chars[length] = 0;

  return string_allocate(heap_chars, length, hash);
}

//=======================================================================//
// Value
//=======================================================================//

static bool value_equals(Value a, Value b) {
  if (a.type != b.type) return false;
  switch (a.type) {
    case VAL_BOOL:
      return a.as.boolean == b.as.boolean;
    case VAL_NIL:
      return true;
    case VAL_NUMBER:
      return a.as.number == b.as.number;
    case VAL_OBJECT:
      return a.as.object == b.as.object;
  }
}

static void value_print(Value value) {
  switch (value.type) {
    case VAL_BOOL:
      printf(value.as.boolean ? "true" : "false");
      break;
    case VAL_NIL:
      printf("nil");
      break;
    case VAL_NUMBER:
      printf("%g", value.as.number);
      break;
    case VAL_OBJECT:
      object_print(value);
      break;
  }
}

static void value_mark(Value value) {
  if (!IS_OBJECT(value)) return;
  object_mark(AS_OBJECT(value));
}

//=======================================================================//
// Value arrays
//=======================================================================//

static void value_array_init(ValueArray *array) {
  array->count = 0;
  array->capacity = 0;
  array->values = NULL;
}

static void value_array_free(ValueArray *array) {
  ARRAY_FREE(uint8_t, array->values, array->capacity);
  value_array_init(array);
}

static void value_array_write(ValueArray *array, Value value) {
  if (array->capacity < array->count + 1) {
    int old_capacity = array->capacity;
    array->capacity = array_grow_capacity(old_capacity);
    array->values =
        ARRAY_GROW(array->values, Value, old_capacity, array->capacity);
  }
  array->values[array->count++] = value;
}

//=======================================================================//
// HashTable of Values
//=======================================================================//

struct Entry {
  String *key;
  Value value;
};

static void table_init(Table *table) {
  table->count = 0;
  table->capacity = 0;
  table->entries = NULL;
}

static void table_free(Table *table) {
  ARRAY_FREE(Entry, table->entries, table->capacity);
  table_init(table);
}

static Entry *table_find_entry(Entry *entries, int capacity, String *key) {
  uint32_t index = key->hash % capacity;
  Entry *tombstone = NULL;

  for (;;) {
    Entry *entry = &entries[index];
    if (entry->key == NULL) {
      if (IS_NIL(entry->value)) {
        return tombstone != NULL ? tombstone : entry;
      } else {
        // We found a tombstone
        if (tombstone == NULL) tombstone = entry;
      }
    } else if (entry->key == key) {
      return entry;
    }
    index = (index + 1) % capacity;
  }
}

static void table_adjust_capacity(Table *table, int capacity) {
  Entry *entries = ALLOCATE(Entry, capacity);
  for (int i = 0; i < capacity; i++) {
    entries[i].key = NULL;
    entries[i].value = NIL;
  }

  table->count = 0;
  for (int i = 0; i < table->capacity; i++) {
    Entry *entry = &table->entries[i];
    if (entry->key == NULL) continue;
    Entry *dest = table_find_entry(entries, capacity, entry->key);
    dest->key = entry->key;
    dest->value = entry->value;
    table->count++;
  }

  ARRAY_FREE(Entry, table->entries, table->capacity);
  table->entries = entries;
  table->capacity = capacity;
}

static bool table_get(Table *table, String *key, Value *value) {
  if (table->count == 0) return false;

  Entry *entry = table_find_entry(table->entries, table->capacity, key);
  if (entry->key == NULL) return false;

  *value = entry->value;
  return true;
}

static bool table_set(Table *table, String *key, Value value) {
  if (table->count + 1 > table->capacity * TABLE_MAX_LOAD) {
    int capacity = array_grow_capacity(table->capacity);
    table_adjust_capacity(table, capacity);
  }

  Entry *entry = table_find_entry(table->entries, table->capacity, key);

  bool is_new_key = entry->key == NULL;
  if (is_new_key && IS_NIL(entry->value)) table->count++;

  entry->key = key;
  entry->value = value;

  return is_new_key;
}

static bool table_delete(Table *table, String *key) {
  if (table->count == 0) return false;

  Entry *entry = table_find_entry(table->entries, table->capacity, key);
  if (entry->key == NULL) return false;

  // Place a tombstone in the entry.
  entry->key = NULL;
  entry->value = BOOL(true);

  return true;
}

static void table_add_all(Table *from, Table *to) {
  for (int i = 0; i < from->capacity; i++) {
    Entry *entry = &from->entries[i];
    if (entry->key != NULL) {
      table_set(to, entry->key, entry->value);
    }
  }
}

static String *table_find_string(Table *table, const char *chars, int length,
                                 uint32_t hash) {
  if (table->count == 0) return NULL;
  uint32_t index = hash % table->capacity;

  for (;;) {
    Entry *entry = &table->entries[index];

    if (entry->key == NULL && IS_NIL(entry->value)) {
      return NULL;
    } else if (entry->key->length == length && entry->key->hash == hash &&
               strncmp(entry->key->chars, chars, length) == 0) {
      return entry->key;
    }

    index = (index + 1) % table->capacity;
  }
}

static void table_mark(Table *table) {
  for (int i = 0; i < table->capacity; i++) {
    Entry *entry = &table->entries[i];
    object_mark((Object *)entry->key);
    value_mark(entry->value);
  }
}

//=======================================================================//
// Chunk of Instructions
//=======================================================================//

static void chunk_init(Chunk *chunk) {
  chunk->count = 0;
  chunk->capacity = 0;
  chunk->code = NULL;
  chunk->lines = NULL;
  value_array_init(&chunk->constants);
}

static void chunk_free(Chunk *chunk) {
  ARRAY_FREE(uint8_t, chunk->code, chunk->capacity);
  ARRAY_FREE(int, chunk->lines, chunk->capacity);
  value_array_free(&chunk->constants);
  chunk_init(chunk);
}

static void chunk_write(Chunk *chunk, uint8_t byte, int line) {
  if (chunk->capacity < chunk->count + 1) {
    int old_capacity = chunk->capacity;
    chunk->capacity = array_grow_capacity(old_capacity);
    chunk->code =
        ARRAY_GROW(chunk->code, uint8_t, old_capacity, chunk->capacity);
    chunk->lines = ARRAY_GROW(chunk->lines, int, old_capacity, chunk->capacity);
  }
  chunk->code[chunk->count] = byte;
  chunk->lines[chunk->count] = line;
  chunk->count += 1;
}

static int chunk_add_constant(Chunk *chunk, Value value) {
  vm_push(value);
  value_array_write(&chunk->constants, value);
  vm_pop();
  assert(chunk->constants.count <= 256);
  return chunk->constants.count - 1;
}

//=======================================================================//
// Disassembly
//=======================================================================//

static int disassemble_simple_instruction(const char *name, int offset) {
  printf("%s\n", name);
  return offset + 1;
}

static int disassemble_constant_instruction(const char *name, Chunk *chunk,
                                            int offset) {
  uint8_t constant = chunk->code[offset + 1];
  printf("%-16s %4d '", name, constant);
  value_print(chunk->constants.values[constant]);
  printf("'\n");
  return offset + 2;
}

static int disassemble_byte_instruction(const char *name, Chunk *chunk,
                                        int offset) {
  uint8_t slot = chunk->code[offset + 1];
  printf("%-16s %4d\n", name, slot);
  return offset + 2;
}

static int disassemble_jmp_instruction(const char *name, int sign, Chunk *chunk,
                                       int offset) {
  uint16_t jump = (uint16_t)(chunk->code[offset + 1] << 8);
  jump |= chunk->code[offset + 2];
  printf("%-16s %4d -> %d\n", name, offset, offset + 3 + sign * jump);
  return offset + 3;
}

static int disassemble_invoke_instruction(const char *name, Chunk *chunk,
                                          int offset) {
  uint8_t constant = chunk->code[offset + 1];
  uint8_t arg_count = chunk->code[offset + 2];
  printf("%-16s (%d args) %4d '", name, arg_count, constant);
  value_print(chunk->constants.values[constant]);
  printf("'\n");
  return offset + 3;
}

static int disassemble_instruction(Chunk *chunk, int offset) {
  printf("%04d ", offset);
  if (offset > 0 && chunk->lines[offset] == chunk->lines[offset - 1]) {
    printf("   | ");
  } else {
    printf("%4d ", chunk->lines[offset]);
  }
  uint8_t instruction = chunk->code[offset];
#define CASE_BYTE(label) \
  case label:            \
    return disassemble_byte_instruction(#label, chunk, offset)
#define CASE_CONST(label) \
  case label:             \
    return disassemble_constant_instruction(#label, chunk, offset)
#define CASE_INVOKE(label) \
  case label:              \
    return disassemble_invoke_instruction(#label, chunk, offset)
#define CASE_JMP(label, sign) \
  case label:                 \
    return disassemble_jmp_instruction(#label, sign, chunk, offset)
#define CASE_SIMPLE(label) \
  case label:              \
    return disassemble_simple_instruction(#label, offset)
  switch (instruction) {
    // Literals
    CASE_CONST(OP_CONST);
    CASE_SIMPLE(OP_NIL);
    CASE_SIMPLE(OP_TRUE);
    CASE_SIMPLE(OP_FALSE);
    // Getters/Setters
    CASE_BYTE(OP_GET_LOCAL);
    CASE_BYTE(OP_SET_LOCAL);
    CASE_CONST(OP_GET_GLOBAL);
    CASE_CONST(OP_SET_GLOBAL);
    CASE_CONST(OP_GET_PROP);
    CASE_CONST(OP_SET_PROP);
    CASE_CONST(OP_GET_SUPER);
    CASE_BYTE(OP_GET_UPVALUE);
    CASE_BYTE(OP_SET_UPVALUE);
    // Arithmetic operations
    CASE_SIMPLE(OP_NEG);
    CASE_SIMPLE(OP_ADD);
    CASE_SIMPLE(OP_SUB);
    CASE_SIMPLE(OP_MUL);
    CASE_SIMPLE(OP_DIV);
    // Comparisons
    CASE_SIMPLE(OP_NOT);
    CASE_SIMPLE(OP_EQUAL);
    CASE_SIMPLE(OP_GREATER);
    CASE_SIMPLE(OP_LESS);
    // Jumps
    CASE_JMP(OP_JMP, 1);
    CASE_JMP(OP_JMP_IF_FALSE, 1);
    CASE_JMP(OP_LOOP, -1);
    CASE_BYTE(OP_CALL);
    // Fast calls (Invokes)
    CASE_INVOKE(OP_SUPER_INVOKE);
    CASE_INVOKE(OP_INVOKE);
    // Closures
    CASE_SIMPLE(OP_CLOSE_UPVALUE);
    // Class
    CASE_CONST(OP_CLASS);
    CASE_CONST(OP_INHERIT);
    CASE_CONST(OP_METHOD);
    // Misc
    CASE_CONST(OP_DEFINE_GLOBAL);
    CASE_SIMPLE(OP_POP);
    CASE_SIMPLE(OP_PRINT);
    CASE_SIMPLE(OP_RET);
    case OP_CLOSURE: {
      offset++;
      uint8_t constant = chunk->code[offset++];
      printf("%-16s %4d ", "OP_CLOSURE", constant);
      value_print(chunk->constants.values[constant]);
      printf("\n");
      Function *function = AS_FUNCTION(chunk->constants.values[constant]);
      for (int j = 0; j < function->upvalue_count; j++) {
        int is_local = chunk->code[offset++];
        int index = chunk->code[offset++];
        printf("%04d      |                     %s %d\n", offset - 2,
               is_local ? "local" : "upvalue", index);
      }
      return offset;
    }
    default:
      printf("Unknown opcode %d\n", instruction);
      return offset + 1;
  }
#undef CASE_BYTE
#undef CASE_CONST
#undef CASE_INVOKE
#undef CASE_JMP
#undef CASE_SIMPLE
}

static void disassemble_chunk(Chunk *chunk, const char *name) {
  printf("== %s ==\n", name);

  for (int offset = 0; offset < chunk->count;) {
    offset = disassemble_instruction(chunk, offset);
  }
}

//=======================================================================//
// Scanner
//=======================================================================//

typedef struct {
  const char *start;
  const char *current;
  int line;
} Scanner;

static Scanner scanner;

static void scanner_init(const char *source) {
  scanner.start = source;
  scanner.current = source;
  scanner.line = 1;
}

static bool scan_is_end() { return *scanner.current == '\0'; }

static Token scan_make_token(TokenType type) {
  Token token;
  token.type = type;
  token.start = scanner.start;
  token.length = (int)(scanner.current - scanner.start);
  token.line = scanner.line;
  return token;
}

static Token scan_error_token(const char *msg) {
  Token token;
  token.type = TK_ERROR;
  token.start = msg;
  token.length = (int)strlen(msg);
  token.line = scanner.line;
  return token;
}

static char scan_advance() {
  scanner.current++;
  return scanner.current[-1];
}

static char scan_peek() { return *scanner.current; }

static char scan_peek_next() {
  if (scan_is_end()) return '\0';
  return scanner.current[1];
}

static bool scan_match(char expected) {
  if (scan_is_end()) return false;
  if (*scanner.current != expected) return false;
  scanner.current++;
  return true;
}

static void scan_skip_whitespace() {
  for (;;) {
    switch (scan_peek()) {
      case ' ':
      case '\r':
      case '\t':
        scan_advance();
        break;
      case '\n':
        scanner.line++;
        scan_advance();
        break;
      case '/':
        if (scan_peek_next() == '/') {
          while (scan_peek() != '\n' && !scan_is_end()) scan_advance();
        } else {
          return;
        }
        break;
      default:
        return;
    }
  }
}

static Token scan_string() {
  while (scan_peek() != '"' && !scan_is_end()) {
    if (scan_peek() == '\n') scanner.line++;
    scan_advance();
  }
  if (scan_is_end()) return scan_error_token("Unfinished string.");
  scan_advance();
  return scan_make_token(TK_STRING);
}

static Token number() {
  while (isdigit(scan_peek())) scan_advance();
  if (scan_peek() == '.' && isdigit(scan_peek_next())) {
    // Consume '.'
    scan_advance();
    while (isdigit(scan_peek())) scan_advance();
  }
  return scan_make_token(TK_NUMBER);
}

static TokenType scan_check_keyword(int start, int length, const char *rest,
                                    TokenType type) {
  if (scanner.current - scanner.start == start + length &&
      memcmp(scanner.start + start, rest, length) == 0) {
    return type;
  }
  return TK_ID;
}

static TokenType scan_id_type() {
  switch (scanner.start[0]) {
    case 'a':
      return scan_check_keyword(1, 2, "nd", TK_AND);
    case 'c':
      return scan_check_keyword(1, 4, "lass", TK_CLASS);
    case 'e':
      return scan_check_keyword(1, 3, "lse", TK_ELSE);
    case 'f':
      if (scanner.current - scanner.start > 1) {
        switch (scanner.start[1]) {
          case 'a':
            return scan_check_keyword(2, 3, "lse", TK_FALSE);
          case 'o':
            return scan_check_keyword(2, 1, "r", TK_FOR);
          case 'u':
            return scan_check_keyword(2, 1, "n", TK_FUN);
          default:
            break;
        }
      }
      break;
    case 'i':
      return scan_check_keyword(1, 1, "f", TK_IF);
    case 'n':
      return scan_check_keyword(1, 2, "il", TK_NIL);
    case 'o':
      return scan_check_keyword(1, 1, "r", TK_OR);
    case 'p':
      return scan_check_keyword(1, 4, "rint", TK_PRINT);
    case 'r':
      return scan_check_keyword(1, 5, "eturn", TK_RETURN);
    case 's':
      return scan_check_keyword(1, 4, "uper", TK_SUPER);
    case 't':
      if (scanner.current - scanner.start > 1) {
        switch (scanner.start[1]) {
          case 'h':
            return scan_check_keyword(2, 2, "is", TK_THIS);
          case 'r':
            return scan_check_keyword(2, 2, "ue", TK_TRUE);
          default:
            break;
        }
      }
      break;
    case 'v':
      return scan_check_keyword(1, 2, "ar", TK_VAR);
    case 'w':
      return scan_check_keyword(1, 4, "hile", TK_WHILE);
  }
  return TK_ID;
}

static Token scan_id() {
  while (isalnum(scan_peek()) || scan_peek() == '_') scan_advance();
  return scan_make_token(scan_id_type());
}

static Token scan_token() {
  scan_skip_whitespace();
  scanner.start = scanner.current;
  if (scan_is_end()) return scan_make_token(TK_EOF);
  char c = scan_advance();
  if (isalpha(c) || c == '_') return scan_id();
  if (isdigit(c)) return number();
  switch (c) {
    case '(':
      return scan_make_token(TK_LPAREN);
    case ')':
      return scan_make_token(TK_RPAREN);
    case '{':
      return scan_make_token(TK_LBRACE);
    case '}':
      return scan_make_token(TK_RBRACE);
    case ';':
      return scan_make_token(TK_SEMI);
    case ',':
      return scan_make_token(TK_COMMA);
    case '.':
      return scan_make_token(TK_DOT);
    case '-':
      return scan_make_token(TK_MINUS);
    case '+':
      return scan_make_token(TK_PLUS);
    case '/':
      return scan_make_token(TK_SLASH);
    case '*':
      return scan_make_token(TK_STAR);
    case '!':
      return scan_make_token(scan_match('=') ? TK_BANG_EQUAL : TK_BANG);
    case '=':
      return scan_make_token(scan_match('=') ? TK_EQUAL_EQUAL : TK_EQUAL);
    case '<':
      return scan_make_token(scan_match('=') ? TK_LESS_EQUAL : TK_LESS);
    case '>':
      return scan_make_token(scan_match('=') ? TK_GREATER_EQUAL : TK_GREATER);
    case '"':
      return scan_string();
    default:
      return scan_error_token("Unexpected character.");
  }
}

//=======================================================================//
// Parser (Pratt)
//=======================================================================//

typedef enum {
  PREC_NONE,
  PREC_ASSIGN,
  PREC_OR,
  PREC_AND,
  PREC_EQ,
  PREC_CMP,
  PREC_TERM,
  PREC_FACTOR,
  PREC_UNARY,
  PREC_CALL,
  PREC_PRIMARY,
} Precedence;

typedef void (*ParseFn)(bool);

typedef struct {
  ParseFn prefix;
  ParseFn infix;
  Precedence precedence;
} ParseRule;

typedef struct {
  Token current;
  Token previous;
  bool had_error;
  bool panic_mode;
} Parser;

static Parser parser;

static void parse_literal(bool can_assign);
static void parse_number(bool can_assign);
static void parse_string(bool can_assign);
static void parse_group(bool can_assign);
static void parse_unary(bool can_assign);
static void parse_binary(bool can_assign);
static void parse_and(bool can_assign);
static void parse_or(bool can_assign);
static void parse_this(bool can_assign);
static void parse_super(bool can_assign);
static void parse_dot(bool can_assign);
static void parse_variable(bool can_assign);
static void parse_call(bool can_assign);
static void parse_expression();
static void parse_statement();
static void parse_var_declaration();
static void parse_declaration();

static ParseRule parse_rules[] = {
    {parse_group, parse_call, PREC_CALL},    // TK_LPAREN
    {NULL, NULL, PREC_NONE},                 // TK_RPAREN
    {NULL, NULL, PREC_NONE},                 // TK_RBRACE
    {NULL, NULL, PREC_NONE},                 // TK_RBRACE
    {NULL, NULL, PREC_NONE},                 // TK_COMMA
    {NULL, parse_dot, PREC_CALL},            // TK_DOT
    {parse_unary, parse_binary, PREC_TERM},  // TK_MINUS
    {NULL, parse_binary, PREC_TERM},         // TK_PLUS
    {NULL, NULL, PREC_NONE},                 // TK_SEMI
    {NULL, parse_binary, PREC_FACTOR},       // TK_SLASH
    {NULL, parse_binary, PREC_FACTOR},       // TK_STAR
    {parse_unary, NULL, PREC_NONE},          // TK_BANG
    {NULL, parse_binary, PREC_EQ},           // TK_BANG_EQUAL
    {NULL, NULL, PREC_NONE},                 // TK_EQUAL
    {NULL, parse_binary, PREC_EQ},           // TK_EQUAL_EQUAL
    {NULL, parse_binary, PREC_CMP},          // TK_GREATER
    {NULL, parse_binary, PREC_CMP},          // TK_GREATER_EQUAL
    {NULL, parse_binary, PREC_CMP},          // TK_LESS
    {NULL, parse_binary, PREC_CMP},          // TK_LESS_EQUAL
    {parse_variable, NULL, PREC_NONE},       // TK_ID
    {parse_string, NULL, PREC_NONE},         // TK_STRING
    {parse_number, NULL, PREC_NONE},         // TK_NUMBER
    {NULL, parse_and, PREC_AND},             // TK_AND
    {NULL, NULL, PREC_NONE},                 // TK_CLASS
    {NULL, NULL, PREC_NONE},                 // TK_ELSE
    {parse_literal, NULL, PREC_NONE},        // TK_FALSE
    {NULL, NULL, PREC_NONE},                 // TK_FOR
    {NULL, NULL, PREC_NONE},                 // TK_FUN
    {NULL, NULL, PREC_NONE},                 // TK_IF
    {parse_literal, NULL, PREC_NONE},        // TK_NIL
    {NULL, parse_or, PREC_OR},               // TK_OR
    {NULL, NULL, PREC_NONE},                 // TK_PRINT
    {NULL, NULL, PREC_NONE},                 // TK_RETURN
    {parse_super, NULL, PREC_NONE},          // TK_SUPER
    {parse_this, NULL, PREC_NONE},           // TK_THIS
    {parse_literal, NULL, PREC_NONE},        // TK_TRUE
    {NULL, NULL, PREC_NONE},                 // TK_VAR
    {NULL, NULL, PREC_NONE},                 // TK_WHILE
    {NULL, NULL, PREC_NONE},                 // TK_ERROR
    {NULL, NULL, PREC_NONE},                 // TK_EOF
};

static_assert((sizeof(parse_rules) / sizeof(ParseRule)) == TK_EOF + 1,
              "Size of parser rules.");

static void parser_error_at(Token *token, const char *message) {
  if (parser.panic_mode) return;
  parser.panic_mode = true;

  fprintf(stderr, "[line %d] Error", token->line);

  if (token->type == TK_EOF) {
    fprintf(stderr, " at end");
  } else if (token->type == TK_ERROR) {
    // Nothing
  } else {
    fprintf(stderr, " at '%.*s'", token->length, token->start);
  }

  fprintf(stderr, ": %s\n", message);
  parser.had_error = true;
}

static void parser_error_at_current(const char *message) {
  parser_error_at(&parser.current, message);
}

static void parser_error(const char *message) {
  parser_error_at(&parser.previous, message);
}

static void parser_advance() {
  parser.previous = parser.current;
  for (;;) {
    parser.current = scan_token();
    if (parser.current.type != TK_ERROR) break;
    parser_error_at_current(parser.current.start);
  }
}

static void parser_consume(TokenType type, const char *message) {
  if (parser.current.type == type) {
    parser_advance();
    return;
  }
  parser_error_at_current(message);
}

static bool parser_check(TokenType type) { return parser.current.type == type; }

static bool parser_match(TokenType type) {
  if (!parser_check(type)) return false;
  parser_advance();
  return true;
}

static void parser_synchronize() {
  parser.panic_mode = false;
  while (parser.current.type != TK_EOF) {
    if (parser.previous.type == TK_SEMI) return;
    switch (parser.current.type) {
      case TK_CLASS:
      case TK_FUN:
      case TK_VAR:
      case TK_FOR:
      case TK_IF:
      case TK_WHILE:
      case TK_PRINT:
      case TK_RETURN:
        return;
      default:
          /* Nothing */;
    }
    parser_advance();
  }
}

static uint8_t parser_id_constant(Token *name) {
  return compiler_make_constant(OBJECT(string_copy(name->start, name->length)));
}

static ParseRule *parse_rule(TokenType type) { return &parse_rules[type]; }

static void parse_precedence(Precedence prec) {
  parser_advance();
  ParseFn prefix_rule = parse_rule(parser.previous.type)->prefix;
  if (prefix_rule == NULL) {
    parser_error("Expect expression.");
    return;
  }

  bool can_assign = prec <= PREC_ASSIGN;
  prefix_rule(can_assign);

  while (prec <= parse_rule(parser.current.type)->precedence) {
    parser_advance();
    parse_rule(parser.previous.type)->infix(can_assign);
  }
}

static void parse_number(UNUSED bool can_assign) {
  double value = strtod(parser.previous.start, NULL);
  emit_constant(NUMBER(value));
}

static void parse_string(UNUSED bool can_assign) {
  emit_constant(OBJECT(
      string_copy(parser.previous.start + 1, parser.previous.length - 2)));
}

static void parse_literal(UNUSED bool can_assign) {
  switch (parser.previous.type) {
    case TK_FALSE:
      emit_byte(OP_FALSE);
      break;
    case TK_NIL:
      emit_byte(OP_NIL);
      break;
    case TK_TRUE:
      emit_byte(OP_TRUE);
      break;
    default:
      assert(0);
  }
}

static void parse_unary(UNUSED bool can_assign) {
  // Remember the operator.
  TokenType operator_type = parser.previous.type;

  // Compiler the operand.
  parse_precedence(PREC_UNARY);

  // Emit the operator instruction
  switch (operator_type) {
    case TK_BANG:
      emit_byte(OP_NOT);
      break;
    case TK_MINUS:
      emit_byte(OP_NEG);
      break;
    default:
      // Unreachable
      assert(0);
  }
}

static void parse_binary(UNUSED bool can_assign) {
  // Remember the operator.
  TokenType operator_type = parser.previous.type;

  // Compile the right operand.
  ParseRule *rule = parse_rule(operator_type);
  parse_precedence((Precedence)(rule->precedence + 1));

  // Emit the operator instruction.
  switch (operator_type) {
    case TK_PLUS:
      emit_byte(OP_ADD);
      break;
    case TK_MINUS:
      emit_byte(OP_SUB);
      break;
    case TK_STAR:
      emit_byte(OP_MUL);
      break;
    case TK_SLASH:
      emit_byte(OP_DIV);
      break;
    case TK_BANG_EQUAL:
      emit_bytes(OP_EQUAL, OP_NOT);
      break;
    case TK_EQUAL_EQUAL:
      emit_byte(OP_EQUAL);
      break;
    case TK_GREATER:
      emit_byte(OP_GREATER);
      break;
    case TK_GREATER_EQUAL:
      emit_bytes(OP_LESS, OP_NOT);
      break;
    case TK_LESS:
      emit_byte(OP_LESS);
      break;
    case TK_LESS_EQUAL:
      emit_bytes(OP_GREATER, OP_NOT);
      break;
    default:
      // Unreachable.
      assert(0);
  }
}

static void parse_and(UNUSED bool can_assign) {
  int end_jmp = emit_jump(OP_JMP_IF_FALSE);
  emit_byte(OP_POP);
  parse_precedence(PREC_AND);
  emit_patch_jump(end_jmp);
}

static void parse_or(UNUSED bool can_assign) {
  int else_jmp = emit_jump(OP_JMP_IF_FALSE);
  int end_jmp = emit_jump(OP_JMP);
  emit_patch_jump(else_jmp);
  emit_byte(OP_POP);
  parse_precedence(PREC_OR);
  emit_patch_jump(end_jmp);
}

static void parse_group(UNUSED bool can_assign) {
  parse_expression();
  parser_consume(TK_RPAREN, "Expect ')' after expression.");
}

static uint8_t parse_argument_list() {
  uint8_t arg_count = 0;
  if (!parser_check(TK_RPAREN)) {
    do {
      parse_expression();
      if (arg_count == 255) {
        parser_error("Cannot have more than 255 arguments.");
      }
      arg_count++;
    } while (parser_match(TK_COMMA));
  }
  parser_consume(TK_RPAREN, "Expect ')' after arguments.");
  return arg_count;
}

static void parse_call(UNUSED bool can_assign) {
  uint8_t arg_count = parse_argument_list();
  emit_bytes(OP_CALL, arg_count);
}

static void parse_expression() { parse_precedence(PREC_ASSIGN); }

static void parse_print() {
  parse_expression();
  parser_consume(TK_SEMI, "Expect ';' after value.");
  emit_byte(OP_PRINT);
}

static void parse_expr_statement() {
  parse_expression();
  parser_consume(TK_SEMI, "Expect ';' after expression.");
  emit_byte(OP_POP);
}

static void parse_block() {
  while (!parser_check(TK_RBRACE) && !parser_check(TK_EOF)) {
    parse_declaration();
  }
  parser_consume(TK_RBRACE, "Expect '}' after block.");
}

static void parse_if() {
  parser_consume(TK_LPAREN, "Expect '(' after 'if'.");
  parse_expression();
  parser_consume(TK_RPAREN, "Expect ')' after condition.");

  int then_jmp = emit_jump(OP_JMP_IF_FALSE);
  emit_byte(OP_POP);
  parse_statement();

  int else_jmp = emit_jump(OP_JMP);
  emit_byte(OP_POP);
  emit_patch_jump(then_jmp);

  if (parser_match(TK_ELSE)) parse_statement();
  emit_patch_jump(else_jmp);
}

static void parse_while() {
  int loop_start = current_chunk()->count;
  parser_consume(TK_LPAREN, "Expect '(' after 'while'.");
  parse_expression();
  parser_consume(TK_RPAREN, "Expect ')' after condition.");

  int exit_jump = emit_jump(OP_JMP_IF_FALSE);
  emit_byte(OP_POP);
  parse_statement();

  emit_loop(loop_start);

  emit_patch_jump(exit_jump);
  emit_byte(OP_POP);
}

static void parse_for() {
  scope_begin();
  parser_consume(TK_LPAREN, "Expect '(' after 'for'.");

  // Initializer clause.
  if (parser_match(TK_SEMI)) {
    // No initializer.
  } else if (parser_match(TK_VAR)) {
    parse_var_declaration();
  } else {
    parse_expr_statement();
  }

  int loop_start = current_chunk()->count;

  // Condition clause.
  int exit_jump = -1;
  if (!parser_match(TK_SEMI)) {
    parse_expression();
    parser_consume(TK_SEMI, "Expect ';' after loop condition.");

    // Jump out of the loop if the condition is false.
    exit_jump = emit_jump(OP_JMP_IF_FALSE);
    emit_byte(OP_POP);  // Condition.
  }

  // Increment clause.
  if (!parser_match(TK_RPAREN)) {
    int body_jump = emit_jump(OP_JMP);

    int increment_start = current_chunk()->count;
    parse_expression();
    emit_byte(OP_POP);
    parser_consume(TK_RPAREN, "Expect ')' after for clauses.");

    emit_loop(loop_start);
    loop_start = increment_start;
    emit_patch_jump(body_jump);
  }

  // Body statement.
  parse_statement();
  emit_loop(loop_start);

  if (exit_jump != -1) {
    emit_patch_jump(exit_jump);
    emit_byte(OP_POP);  // Condition.
  }

  scope_end();
}

static void parse_return() {
  if (compiler_is_script()) {
    parser_error("Cannot return from top-level code.");
  }

  if (parser_match(TK_SEMI)) {
    emit_return();
  } else {
    if (compiler_is_init()) {
      parser_error("Cannot return a value from an initializer.");
    }
    parse_expression();
    parser_consume(TK_SEMI, "Expect ';' after return value.");
    emit_byte(OP_RET);
  }
}

static void parse_statement() {
  if (parser_match(TK_PRINT)) {
    parse_print();
  } else if (parser_match(TK_RETURN)) {
    parse_return();
  } else if (parser_match(TK_IF)) {
    parse_if();
  } else if (parser_match(TK_WHILE)) {
    parse_while();
  } else if (parser_match(TK_FOR)) {
    parse_for();
  } else if (parser_match(TK_LBRACE)) {
    scope_begin();
    parse_block();
    scope_end();
  } else {
    parse_expr_statement();
  }
}

static void parse_named_variable(Token name, bool can_assign) {
  uint8_t get_op, set_op;
  int arg = scope_resolve_local(&name);
  if (arg != -1) {
    get_op = OP_GET_LOCAL;
    set_op = OP_SET_LOCAL;
  } else if ((arg = scope_resolve_upvalue(&name)) != -1) {
    get_op = OP_GET_UPVALUE;
    set_op = OP_SET_UPVALUE;
  } else {
    arg = parser_id_constant(&name);
    get_op = OP_GET_GLOBAL;
    set_op = OP_SET_GLOBAL;
  }
  if (can_assign && parser_match(TK_EQUAL)) {
    parse_expression();
    emit_bytes(set_op, (uint8_t)arg);
  } else {
    emit_bytes(get_op, (uint8_t)arg);
  }
}

static void parse_dot(bool can_assign) {
  parser_consume(TK_ID, "Expect proeprty name after '.'.");
  uint8_t name = parser_id_constant(&parser.previous);
  if (can_assign && parser_match(TK_EQUAL)) {
    parse_expression();
    emit_bytes(OP_SET_PROP, name);
  } else if (parser_match(TK_LPAREN)) {
    uint8_t arg_count = parse_argument_list();
    emit_bytes(OP_INVOKE, name);
    emit_byte(arg_count);
  } else {
    emit_bytes(OP_GET_PROP, name);
  }
}

static void parse_variable(bool can_assign) {
  parse_named_variable(parser.previous, can_assign);
}

static void parse_declare_variable() {
  // Globals are implicitly declared.
  if (scope_depth() == 0) return;
  Token *name = &parser.previous;
  if (scope_is_declared(name)) {
    parser_error("Variable with this name already declared in this scope.");
  }
  scope_add_local(*name);
}

static uint8_t parse_new_variable(const char *msg) {
  parser_consume(TK_ID, msg);
  parse_declare_variable();
  if (scope_depth() > 0) return 0;
  return parser_id_constant(&parser.previous);
}

static void parse_fun_declaration() {
  uint8_t global = parse_new_variable("Expect function name.");
  scope_mark_initialized();
  compile_function(TYPE_FUNCTION);
  emit_define_variable(global);
}

static void parse_var_declaration() {
  uint8_t global = parse_new_variable("Expect variable name.");

  if (parser_match(TK_EQUAL)) {
    parse_expression();
  } else {
    emit_byte(OP_NIL);
  }
  parser_consume(TK_SEMI, "Expect ';' after variable declaration.");

  emit_define_variable(global);
}

static void parse_method() {
  parser_consume(TK_ID, "Expect method name.");
  uint8_t constant = parser_id_constant(&parser.previous);
  FunctionType type = TYPE_METHOD;
  if (parser.previous.length == 4 &&
      strncmp(parser.previous.start, "init", 4) == 0) {
    type = TYPE_INIT;
  }
  compile_function(type);
  emit_bytes(OP_METHOD, constant);
}

typedef struct ClassCompiler {
  struct ClassCompiler *enclosing;
  Token name;
  bool has_super;
} ClassCompiler;
static ClassCompiler *current_class;

static Token parser_synthetic_token(const char *name) {
  Token token;
  token.start = name;
  token.length = (int)strlen(name);
  return token;
}

static void parse_this(UNUSED bool can_assign) {
  if (current_class == NULL) {
    parser_error("Cannot use 'this' outside of a class.");
    return;
  }
  parse_variable(false);
}

static void parse_super(UNUSED bool can_assign) {
  if (current_class == NULL) {
    parser_error("Cannot use 'super' outside of a class.");
  } else if (!current_class->has_super) {
    parser_error("Cannot use 'super' in a class with no superclass.");
  }
  parser_consume(TK_DOT, "Expect '. after 'super'.");
  parser_consume(TK_ID, "Expect superclass method name.");
  uint8_t name = parser_id_constant(&parser.previous);
  parse_named_variable(parser_synthetic_token("this"), false);
  if (parser_match(TK_LPAREN)) {
    uint8_t arg_count = parse_argument_list();
    parse_named_variable(parser_synthetic_token("super"), false);
    emit_bytes(OP_SUPER_INVOKE, name);
    emit_byte(arg_count);
  } else {
    parse_named_variable(parser_synthetic_token("super"), false);
    emit_bytes(OP_GET_SUPER, name);
  }
}

static void parse_class_declaration() {
  parser_consume(TK_ID, "Expect class name.");
  Token class_name = parser.previous;
  uint8_t name_constant = parser_id_constant(&parser.previous);
  parse_declare_variable();

  emit_bytes(OP_CLASS, name_constant);
  emit_define_variable(name_constant);

  ClassCompiler class_compiler;
  class_compiler.name = parser.previous;
  class_compiler.enclosing = current_class;
  class_compiler.has_super = false;
  current_class = &class_compiler;

  if (parser_match(TK_LESS)) {
    parser_consume(TK_ID, "Expect sueprclass name.");
    parse_variable(false);
    if (scope_identifiers_equal(&class_name, &parser.previous)) {
      parser_error("A class cannot inherit from itself.");
    }
    parse_named_variable(class_name, false);
    emit_byte(OP_INHERIT);
    class_compiler.has_super = true;
  }

  scope_begin();
  scope_add_local(parser_synthetic_token("super"));
  emit_define_variable(0);

  parse_named_variable(class_name, false);
  parser_consume(TK_LBRACE, "Expect '{' before class body.");
  while (!parser_check(TK_RBRACE) && !parser_check(TK_EOF)) {
    parse_method();
  }
  parser_consume(TK_RBRACE, "Expect '}' after class body");
  emit_byte(OP_POP);

  if (class_compiler.has_super) {
    scope_end();
  }

  current_class = current_class->enclosing;
}

static void parse_declaration() {
  if (parser_match(TK_CLASS)) {
    parse_class_declaration();
  } else if (parser_match(TK_FUN)) {
    parse_fun_declaration();
  } else if (parser_match(TK_VAR)) {
    parse_var_declaration();
  } else {
    parse_statement();
  }
  if (parser.panic_mode) parser_synchronize();
}

static void parse() {
  parser.had_error = false;
  parser.panic_mode = false;
  parser_advance();
  while (!parser_match(TK_EOF)) {
    parse_declaration();
  }
}

//=======================================================================//
// Emitter
//=======================================================================//

static void emit_byte(uint8_t byte) {
  chunk_write(current_chunk(), byte, parser.previous.line);
}

static void emit_bytes(uint8_t byte1, uint8_t byte2) {
  emit_byte(byte1);
  emit_byte(byte2);
}

static void emit_constant(Value value) {
  emit_bytes(OP_CONST, compiler_make_constant(value));
}

static void emit_define_variable(uint8_t global) {
  if (scope_depth() > 0) {
    scope_mark_initialized();
    return;
  }
  emit_bytes(OP_DEFINE_GLOBAL, global);
}

static int emit_jump(uint8_t instruction) {
  emit_byte(instruction);
  emit_byte(0xFF);
  emit_byte(0xFF);
  return current_chunk()->count - 2;
}

static void emit_patch_jump(int offset) {
  // -2 to adjust for the bytecode for the jump offset itself.
  int jump = current_chunk()->count - offset - 2;
  if (jump > UINT16_MAX) {
    parser_error("Too much code to jump over.");
  }
  current_chunk()->code[offset] = (jump >> 8) & 0xFF;
  current_chunk()->code[offset + 1] = jump & 0xFF;
}

static void emit_loop(int loop_start) {
  emit_byte(OP_LOOP);

  int offset = current_chunk()->count - loop_start + 2;
  if (offset > UINT16_MAX) parser_error("Loop body too large.");

  emit_byte((offset >> 8) & 0xFF);
  emit_byte(offset & 0xFF);
}

static void emit_return() {
  if (compiler_is_init()) {
    emit_bytes(OP_GET_LOCAL, 0);
  } else {
    emit_byte(OP_NIL);
  }
  emit_byte(OP_RET);
}

//=======================================================================//
// Compiler
//=======================================================================//

typedef struct {
  Token name;
  int depth;
  bool is_captured;
} Local;

typedef struct {
  uint8_t index;
  bool is_local;
} UpvalueIndex;

typedef struct compiler {
  struct compiler *enclosing;
  Function *function;
  FunctionType type;
  Local locals[UINT8_MAX + 1];
  int local_count;
  UpvalueIndex upvalues[UINT8_MAX + 1];
  int scope_depth;
} Compiler;

static Compiler *current;

static Chunk *current_chunk() { return &current->function->chunk; }

static bool compiler_is_script() { return current->type == TYPE_SCRIPT; }

static bool compiler_is_init() { return current->type == TYPE_INIT; }

static void compiler_init(Compiler *compiler, FunctionType type) {
  compiler->enclosing = current;
  compiler->function = NULL;
  compiler->type = type;
  compiler->local_count = 0;
  compiler->scope_depth = 0;
  compiler->function = function_new();
  current = compiler;

  if (type != TYPE_SCRIPT) {
    current->function->name =
        string_copy(parser.previous.start, parser.previous.length);
  }

  Local *local = &current->locals[current->local_count++];
  local->depth = 0;
  local->is_captured = false;
  if (type != TYPE_FUNCTION) {
    local->name.start = "this";
    local->name.length = 4;
  } else {
    local->name.start = "";
    local->name.length = 0;
  }
}

static Function *compiler_end() {
  emit_return();
  Function *function = current->function;
#ifdef DEBUG_PRINT_CODE
  if (!parser.had_error) {
    disassemble_chunk(current_chunk(), function->name != NULL
                                           ? function->name->chars
                                           : "<script>");
  }
#endif
  current = current->enclosing;
  return function;
}

static uint8_t compiler_make_constant(Value value) {
  int constant = chunk_add_constant(current_chunk(), value);
  if (constant > UINT8_MAX) {
    parser_error("Too many constants in one chunk.");
    return 0;
  }
  return (uint8_t)constant;
}

static void compile_function(FunctionType type) {
  Compiler compiler;
  compiler_init(&compiler, type);
  scope_begin();

  // Compile the parameter list.
  parser_consume(TK_LPAREN, "Expect '(' after function name.");
  if (!parser_check(TK_RPAREN)) {
    do {
      current->function->arity++;
      if (current->function->arity > 255) {
        parser_error_at_current("Cannot habve more than 255 parameters.");
      }
      uint8_t param_constant = parse_new_variable("Expect parameter name.");
      emit_define_variable(param_constant);
    } while (parser_match(TK_COMMA));
  }
  parser_consume(TK_RPAREN, "Expect ')' after parameters.");

  // The body.
  parser_consume(TK_LBRACE, "Expect '{' before function body.");
  parse_block();

  // Create the function object.
  Function *function = compiler_end();
  emit_bytes(OP_CLOSURE, compiler_make_constant(OBJECT(function)));

  for (int i = 0; i < function->upvalue_count; i++) {
    emit_byte(compiler.upvalues[i].is_local ? 1 : 0);
    emit_byte(compiler.upvalues[i].index);
  }
}

static Function *compile(const char *source) {
  scanner_init(source);
  Compiler compiler;
  compiler_init(&compiler, TYPE_SCRIPT);
  parse();
  Function *function = compiler_end();
  return parser.had_error ? NULL : function;
}

static void compiler_mark_roots() {
  Compiler *compiler = current;
  while (compiler != NULL) {
    object_mark((Object *)compiler->function);
    compiler = compiler->enclosing;
  }
}

//=======================================================================//
// Scope
//=======================================================================//

static void scope_begin() { current->scope_depth++; }

static void scope_end() {
  current->scope_depth--;
  while (current->local_count > 0 &&
         current->locals[current->local_count - 1].depth >
             current->scope_depth) {
    if (current->locals[current->local_count - 1].is_captured) {
      emit_byte(OP_CLOSE_UPVALUE);
    } else {
      emit_byte(OP_POP);
    }
    current->local_count--;
  }
}

static int scope_depth() { return current->scope_depth; }

static void scope_add_local(Token name) {
  assert(current->local_count < UINT8_MAX + 1);
  Local *local = &current->locals[current->local_count++];
  local->name = name;
  local->depth = -1;
  local->is_captured = false;
}

static bool scope_identifiers_equal(Token *a, Token *b) {
  if (a->length != b->length) return false;
  return strncmp(a->start, b->start, a->length) == 0;
}

static bool scope_is_declared(Token *name) {
  for (int i = current->local_count - 1; i >= 0; i--) {
    Local *local = &current->locals[i];
    if (local->depth != -1 && local->depth < current->scope_depth) {
      break;
    }
    if (scope_identifiers_equal(name, &local->name)) {
      return true;
    }
  }
  return false;
}

static void scope_mark_initialized() {
  if (current->scope_depth == 0) return;
  current->locals[current->local_count - 1].depth = current->scope_depth;
}

static int scope_resolve_local_helper(Compiler *compiler, Token *name) {
  for (int i = compiler->local_count - 1; i >= 0; i--) {
    Local *local = &compiler->locals[i];
    if (scope_identifiers_equal(name, &local->name)) {
      return i;
    }
  }
  return -1;
}

static int scope_resolve_local(Token *name) {
  return scope_resolve_local_helper(current, name);
}

static int scope_add_upvalue(Compiler *compiler, uint8_t index, bool is_local) {
  int upvalue_count = compiler->function->upvalue_count;

  for (int i = 0; i < upvalue_count; i++) {
    UpvalueIndex *upvalue = &compiler->upvalues[i];
    if (upvalue->index == index && upvalue->is_local == is_local) {
      return i;
    }
  }

  if (upvalue_count == UINT8_MAX + 1) {
    parser_error("Too many closure variables in function.");
    return 0;
  }

  compiler->upvalues[upvalue_count].is_local = is_local;
  compiler->upvalues[upvalue_count].index = index;
  return compiler->function->upvalue_count++;
}

static int scope_resolve_upvalue_helper(Compiler *compiler, Token *name) {
  if (compiler->enclosing == NULL) return -1;
  int local = scope_resolve_local_helper(compiler->enclosing, name);
  if (local != -1) {
    compiler->enclosing->locals[local].is_captured = true;
    return scope_add_upvalue(compiler, (uint8_t)local, true);
  }
  int upvalue = scope_resolve_upvalue_helper(compiler->enclosing, name);
  if (upvalue != -1) {
    return scope_add_upvalue(compiler, (uint8_t)upvalue, false);
  }
  return -1;
}

static int scope_resolve_upvalue(Token *name) {
  return scope_resolve_upvalue_helper(current, name);
}

//=======================================================================//
// VM
//=======================================================================//

typedef struct {
  Closure *closure;
  uint8_t *ip;
  Value *slots;
} CallFrame;

typedef struct {
  int gray_count;
  int gray_capacity;
  Object **gray_stack;
  size_t bytes_allocated;
  size_t next_gc;
} GC;

struct VM {
  CallFrame frames[FRAMES_MAX];
  int frame_count;
  Value stack[STACK_MAX];
  int stack_size;
  Table globals;
  Table strings;
  Object *objects;
  String *string_init;
  Upvalue *open_upvalues;
  GC gc;
};

static VM vm;

static void vm_stack_reset() {
  vm.stack_size = 0;
  vm.frame_count = 0;
  vm.open_upvalues = NULL;
}

static void vm_init() {
  vm_stack_reset();
  vm.objects = NULL;
  gc_init(&vm.gc);
  table_init(&vm.globals);
  table_init(&vm.strings);
  vm.string_init = NULL;  // To avoid being freed by GC.
  vm.string_init = string_copy("init", 4);
  vm_define_native("clock", native_clock);
}

static void vm_free_objects() {
  Object *object = vm.objects;
  while (object != NULL) {
    Object *next = object->next;
    object_free(object);
    object = next;
  }
  free(vm.gc.gray_stack);
}

static void vm_free() {
  table_free(&vm.globals);
  table_free(&vm.strings);
  vm.string_init = NULL;  // Will be freed by vm_free_objects.
  vm_free_objects();
}

static void vm_push(Value value) {
  vm.stack[vm.stack_size++] = value;
  assert(vm.stack_size < 256);
}

static Value vm_pop() {
  assert(vm.stack_size > 0);
  return vm.stack[--vm.stack_size];
}

static Value vm_peek(int distance) {
  assert(vm.stack_size > distance);
  return vm.stack[vm.stack_size - distance - 1];
}

static bool vm_is_false(Value val) {
  return IS_NIL(val) || (IS_BOOL(val) && !val.as.boolean);
}

static void vm_concat() {
  String *b = AS_STRING(vm_peek(0));
  String *a = AS_STRING(vm_peek(1));

  int length = a->length + b->length;
  char *chars = ALLOCATE(char, length + 1);
  memcpy(chars, a->chars, a->length);
  memcpy(chars + a->length, b->chars, b->length);
  chars[length] = 0;

  String *result = string_take(chars, length);
  vm_pop();
  vm_pop();
  vm_push(OBJECT(result));
}

static void vm_runtime_error(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fputs("\n", stderr);

  for (int i = vm.frame_count - 1; i >= 0; i--) {
    CallFrame *frame = &vm.frames[i];
    Function *function = frame->closure->function;
    // IP is sitting on the next instruction to be executed.
    size_t instr = frame->ip - function->chunk.code - 1;
    int line = function->chunk.lines[instr];
    fprintf(stderr, "[line %d] in ", line);
    if (function->name == NULL) {
      fprintf(stderr, "script\n");
    } else {
      fprintf(stderr, "%s()\n", function->name->chars);
    }
  }

  vm_stack_reset();
}

static bool vm_call(Closure *closure, int arg_count) {
  if (arg_count != closure->function->arity) {
    vm_runtime_error("Expected %d arguments but got %d.",
                     closure->function->arity, arg_count);
    return false;
  }

  if (vm.frame_count == FRAMES_MAX) {
    vm_runtime_error("Stack overflow.");
    return false;
  }

  CallFrame *frame = &vm.frames[vm.frame_count++];
  frame->closure = closure;
  frame->ip = closure->function->chunk.code;
  frame->slots = &vm.stack[vm.stack_size - arg_count - 1];
  return true;
}

static void vm_define_native(const char *name, NativeFn function) {
  vm_push(OBJECT(string_copy(name, (int)strlen(name))));
  vm_push(OBJECT(native_new(function)));
  table_set(&vm.globals, AS_STRING(vm.stack[0]), vm.stack[1]);
  vm_pop();
  vm_pop();
}

static bool vm_call_value(Value callee, int arg_count) {
  if (IS_OBJECT(callee)) {
    switch (AS_OBJECT(callee)->type) {
      case OBJ_CLASS: {
        Class *class = AS_CLASS(callee);
        vm.stack[vm.stack_size - arg_count - 1] = OBJECT(instance_new(class));
        Value initializer;
        if (table_get(&class->methods, vm.string_init, &initializer)) {
          return vm_call(AS_CLOSURE(initializer), arg_count);
        } else if (arg_count != 0) {
          vm_runtime_error("Expected 0 arguments but got %d.", arg_count);
          return false;
        }
        return true;
      }
      case OBJ_CLOSURE:
        return vm_call(AS_CLOSURE(callee), arg_count);
      case OBJ_NATIVE: {
        NativeFn native = AS_NATIVE(callee);
        Value result = native(arg_count, &vm.stack[vm.stack_size - arg_count]);
        vm.stack_size -= arg_count + 1;
        vm_push(result);
        return true;
      }
      case OBJ_METHOD: {
        Method *bound = AS_METHOD(callee);
        vm.stack[vm.stack_size - arg_count - 1] = bound->receiver;
        return vm_call(bound->method, arg_count);
      }
      default:
        // Non-callable object type.
        break;
    }
  }
  vm_runtime_error("Can only call functions and classes.");
  return false;
}

static Upvalue *vm_capture_upvalue(Value *local) {
  Upvalue *prev = NULL;
  Upvalue *upvalue = vm.open_upvalues;

  while (upvalue != NULL && upvalue->location > local) {
    prev = upvalue;
    upvalue = upvalue->next;
  }

  if (upvalue != NULL && upvalue->location == local) return upvalue;

  Upvalue *created_upvalue = upvalue_new(local);
  created_upvalue->next = upvalue;
  if (prev == NULL) {
    vm.open_upvalues = created_upvalue;
  } else {
    prev->next = created_upvalue;
  }

  return created_upvalue;
}

static void vm_close_upvalues(Value *last) {
  while (vm.open_upvalues != NULL && vm.open_upvalues->location >= last) {
    Upvalue *upvalue = vm.open_upvalues;
    upvalue->closed = *upvalue->location;
    upvalue->location = &upvalue->closed;
    vm.open_upvalues = upvalue->next;
  }
}

static void vm_define_method(String *name) {
  Value method = vm_peek(0);
  Class *class = AS_CLASS(vm_peek(1));
  table_set(&class->methods, name, method);
  vm_pop();
}

static bool vm_bind_method(Class *class, String *name) {
  Value method;
  if (!table_get(&class->methods, name, &method)) {
    vm_runtime_error("Undefined property '%s'.", name->chars);
    return false;
  }
  Method *bound = method_new(vm_peek(0), AS_CLOSURE(method));
  vm_pop();
  vm_push(OBJECT(bound));
  return true;
}

static bool vm_invoke_from_class(Class *class, String *name, int arg_count) {
  Value method;
  if (!table_get(&class->methods, name, &method)) {
    vm_runtime_error("Undefiend property '%s'.", name->chars);
    return false;
  }
  return vm_call(AS_CLOSURE(method), arg_count);
}

static bool vm_invoke(String *name, int arg_count) {
  Value receiver = vm_peek(arg_count);
  if (!IS_INSTANCE(receiver)) {
    vm_runtime_error("Only instances have methods.");
    return false;
  }
  Instance *instance = AS_INSTANCE(receiver);
  Value value;
  if (table_get(&instance->fields, name, &value)) {
    vm.stack[vm.stack_size - arg_count - 1] = value;
    return vm_call_value(value, arg_count);
  }
  return vm_invoke_from_class(instance->class, name, arg_count);
}

static InterpretResult vm_run() {
  CallFrame *frame = &vm.frames[vm.frame_count - 1];
#define READ_BYTE() (*frame->ip++)
#define READ_SHORT() \
  (frame->ip += 2, (uint16_t)((frame->ip[-2] << 8 | frame->ip[-1])))
#define READ_CONSTANT() \
  (frame->closure->function->chunk.constants.values[READ_BYTE()])
#define READ_STRING() AS_STRING(READ_CONSTANT())
#define BINARY_OP(type, op)                                 \
  do {                                                      \
    if (!IS_NUMBER(vm_peek(0)) || !IS_NUMBER(vm_peek(1))) { \
      vm_runtime_error("Operands must be numbers.");        \
      return INTERPRET_RUNTIME_ERROR;                       \
    }                                                       \
    double b = vm_pop().as.number;                          \
    double a = vm_pop().as.number;                          \
    vm_push(type(a op b));                                  \
  } while (false)

  for (;;) {
    uint8_t instruction;

#ifdef DEBUG_TRACE_EXECUTION
    printf("          ");
    for (int slot = 0; slot < vm.stack_size; slot++) {
      printf("[ ");
      value_print(vm.stack[slot]);
      printf(" ]");
    }
    printf("\n");
    disassemble_instruction(
        &frame->closure->function->chunk,
        (int)(frame->ip - frame->closure->function->chunk.code));
#endif

    switch (instruction = READ_BYTE()) {
      // Literals
      case OP_CONST: {
        Value constant = READ_CONSTANT();
        vm_push(constant);
        break;
      }
      case OP_NIL:
        vm_push(NIL);
        break;
      case OP_TRUE:
        vm_push(BOOL(true));
        break;
      case OP_FALSE:
        vm_push(BOOL(false));
        break;
      // Getters/Setters
      case OP_GET_LOCAL: {
        uint8_t slot = READ_BYTE();
        vm_push(frame->slots[slot]);
        break;
      }
      case OP_SET_LOCAL: {
        uint8_t slot = READ_BYTE();
        frame->slots[slot] = vm_peek(0);
        break;
      }
      case OP_GET_GLOBAL: {
        String *name = READ_STRING();
        Value value;
        if (!table_get(&vm.globals, name, &value)) {
          vm_runtime_error("Undefined variable '%s'.", name->chars);
          return INTERPRET_RUNTIME_ERROR;
        }
        vm_push(value);
        break;
      }
      case OP_SET_GLOBAL: {
        String *name = READ_STRING();
        if (table_set(&vm.globals, name, vm_peek(0))) {
          table_delete(&vm.globals, name);
          vm_runtime_error("Undefined vairable '%s'.", name->chars);
          return INTERPRET_RUNTIME_ERROR;
        }
        break;
      }
      case OP_GET_PROP: {
        if (!IS_INSTANCE(vm_peek(0))) {
          vm_runtime_error("Only instances have properties.");
          return INTERPRET_RUNTIME_ERROR;
        }
        Instance *instance = AS_INSTANCE(vm_peek(0));
        String *name = READ_STRING();
        Value value;
        if (table_get(&instance->fields, name, &value)) {
          vm_pop();  // instance
          vm_push(value);
          break;
        }
        if (!vm_bind_method(instance->class, name)) {
          return INTERPRET_RUNTIME_ERROR;
        }
        break;
      }
      case OP_SET_PROP: {
        if (!IS_INSTANCE(vm_peek(1))) {
          vm_runtime_error("Only instances have fields.");
          return INTERPRET_RUNTIME_ERROR;
        }
        Instance *instance = AS_INSTANCE(vm_peek(1));
        table_set(&instance->fields, READ_STRING(), vm_peek(0));
        Value value = vm_pop();
        vm_pop();  // instance
        vm_push(value);
        break;
      }
      case OP_GET_SUPER: {
        String *name = READ_STRING();
        Class *super = AS_CLASS(vm_pop());
        if (!vm_bind_method(super, name)) {
          return INTERPRET_RUNTIME_ERROR;
        }
        break;
      }
      case OP_GET_UPVALUE: {
        uint8_t slot = READ_BYTE();
        vm_push(*frame->closure->upvalues[slot]->location);
        break;
      }
      case OP_SET_UPVALUE: {
        uint8_t slot = READ_BYTE();
        *frame->closure->upvalues[slot]->location = vm_peek(0);
        break;
      }
      // Arithmetic operations
      case OP_NEG:
        if (!IS_NUMBER(vm_peek(0))) {
          vm_runtime_error("Operand must be a number.");
          return INTERPRET_RUNTIME_ERROR;
        }
        vm_push(NUMBER(vm_pop().as.number));
        break;
      case OP_ADD: {
        if (IS_STRING(vm_peek(0)) && IS_STRING(vm_peek(1))) {
          vm_concat();
        } else if (IS_NUMBER(vm_peek(0)) && IS_NUMBER(vm_peek(1))) {
          BINARY_OP(NUMBER, +);
        } else {
          vm_runtime_error("Operands must be two numbers or two strings.");
          return INTERPRET_RUNTIME_ERROR;
        }
        break;
      }
      case OP_SUB:
        BINARY_OP(NUMBER, -);
        break;
      case OP_MUL:
        BINARY_OP(NUMBER, *);
        break;
      case OP_DIV:
        BINARY_OP(NUMBER, /);
        break;
      // Comparisons
      case OP_NOT:
        vm_push(BOOL(vm_is_false(vm_pop())));
        break;
      case OP_EQUAL: {
        Value b = vm_pop();
        Value a = vm_pop();
        vm_push(BOOL(value_equals(a, b)));
        break;
      }
      case OP_GREATER:
        BINARY_OP(BOOL, >);
        break;
      case OP_LESS:
        BINARY_OP(BOOL, <);
        break;
      // Jumps
      case OP_JMP: {
        uint16_t offset = READ_SHORT();
        frame->ip += offset;
        break;
      }
      case OP_JMP_IF_FALSE: {
        uint16_t offset = READ_SHORT();
        if (vm_is_false(vm_peek(0))) frame->ip += offset;
        break;
      }
      case OP_LOOP: {
        uint16_t offset = READ_SHORT();
        frame->ip -= offset;
        break;
      }
      case OP_CALL: {
        int arg_count = READ_BYTE();
        if (!vm_call_value(vm_peek(arg_count), arg_count)) {
          return INTERPRET_RUNTIME_ERROR;
        }
        frame = &vm.frames[vm.frame_count - 1];
        break;
      }
      // // Fast calls (Invokes)
      case OP_INVOKE: {
        String *method = READ_STRING();
        int arg_count = READ_BYTE();
        if (!vm_invoke(method, arg_count)) {
          return INTERPRET_RUNTIME_ERROR;
        }
        frame = &vm.frames[vm.frame_count - 1];
        break;
      }
      case OP_SUPER_INVOKE: {
        String *method = READ_STRING();
        int arg_count = READ_BYTE();
        Class *super = AS_CLASS(vm_pop());
        if (!vm_invoke_from_class(super, method, arg_count)) {
          return INTERPRET_RUNTIME_ERROR;
        }
        frame = &vm.frames[vm.frame_count - 1];
        break;
      }
      // Closures
      case OP_CLOSURE: {
        Function *function = AS_FUNCTION(READ_CONSTANT());
        Closure *closure = closure_new(function);
        vm_push(OBJECT(closure));
        for (int i = 0; i < closure->upvalue_count; i++) {
          uint8_t is_local = READ_BYTE();
          uint8_t index = READ_BYTE();
          if (is_local) {
            closure->upvalues[i] = vm_capture_upvalue(frame->slots + index);
          } else {
            closure->upvalues[i] = frame->closure->upvalues[index];
          }
        }
        break;
      }
      case OP_CLOSE_UPVALUE: {
        vm_close_upvalues(&vm.stack[vm.stack_size - 1]);
        vm_pop();
        break;
      }
      // Class
      case OP_CLASS:
        vm_push(OBJECT(class_new(READ_STRING())));
        break;
      case OP_INHERIT: {
        Value super = vm_peek(1);
        if (!IS_CLASS(super)) {
          vm_runtime_error("Superclass must be a class.");
          return INTERPRET_RUNTIME_ERROR;
        }
        Class *sub = AS_CLASS(vm_peek(0));
        table_add_all(&AS_CLASS(super)->methods, &sub->methods);
        vm_pop();
        break;
      }
      case OP_METHOD:
        vm_define_method(READ_STRING());
        break;
      // Misc
      case OP_DEFINE_GLOBAL: {
        String *name = READ_STRING();
        table_set(&vm.globals, name, vm_peek(0));
        vm_pop();
        break;
      }
      case OP_POP:
        vm_pop();
        break;
      case OP_PRINT: {
        value_print(vm_pop());
        printf("\n");
        break;
      }
      case OP_RET: {
        Value result = vm_pop();
        vm_close_upvalues(frame->slots);
        vm.frame_count--;
        if (vm.frame_count == 0) {
          vm_pop();
          return INTERPRET_OK;
        }
        vm.stack_size = (int)(frame->slots - vm.stack);
        vm_push(result);
        frame = &vm.frames[vm.frame_count - 1];
        break;
      }
    }
  }
#undef READ_BYTE
#undef READ_SHORT
#undef READ_CONSTANT
#undef READ_STRING
#undef BINARY_OP
}

static InterpretResult vm_interpret(const char *source) {
  Function *function = compile(source);
  if (function == NULL) return INTERPRET_COMPILE_ERROR;

  vm_push(OBJECT(function));
  Closure *closure = closure_new(function);
  vm_pop();
  vm_push(OBJECT(closure));
  vm_call_value(OBJECT(closure), 0);

  return vm_run();
}

static void vm_add_object(Object *object) {
  object->next = vm.objects;
  vm.objects = object;
}

static void vm_add_internal_string(String *string) {
  vm_push(OBJECT(string));
  table_set(&vm.strings, string, NIL);
  vm_pop();
}

static String *vm_get_internal_string(const char *chars, int length,
                                      uint32_t hash) {
  return table_find_string(&vm.strings, chars, length, hash);
}

//=======================================================================//
// GC
//=======================================================================//

static void *reallocate(void *prev, UNUSED size_t old_size, size_t new_size) {
  vm.gc.bytes_allocated += new_size - old_size;
  if (new_size > old_size) {
#ifdef DEBUG_STRESS_GC
    gc();
#endif
    if (vm.gc.bytes_allocated > vm.gc.next_gc) {
      gc();
    }
  }
  if (new_size == 0) {
    free(prev);
    return NULL;
  }
  return realloc(prev, new_size);
}

static void object_mark(Object *object) {
  if (object == NULL) return;
  if (object->is_marked) return;
#ifdef DEBUG_LOG_GC
  printf("%p mark ", (void *)object);
  value_print(OBJECT(object));
  printf("\n");
#endif
  object->is_marked = true;
  if (vm.gc.gray_capacity < vm.gc.gray_count + 1) {
    vm.gc.gray_capacity = array_grow_capacity(vm.gc.gray_capacity);
    vm.gc.gray_stack =
        realloc(vm.gc.gray_stack, sizeof(Object *) * vm.gc.gray_capacity);
  }
  vm.gc.gray_stack[vm.gc.gray_count++] = object;
}

static void gc_init() {
  vm.gc.bytes_allocated = 0;
  vm.gc.next_gc = 1024 * 1024;
  vm.gc.gray_count = 0;
  vm.gc.gray_capacity = 0;
  vm.gc.gray_stack = NULL;
}

static void gc_mark() {
  for (int i = 0; i < vm.stack_size; i++) {
    value_mark(vm.stack[i]);
  }
  for (int i = 0; i < vm.frame_count; i++) {
    object_mark((Object *)vm.frames[i].closure);
  }
  for (Upvalue *upvalue = vm.open_upvalues; upvalue != NULL;
       upvalue = upvalue->next) {
    object_mark((Object *)upvalue);
  }
  table_mark(&vm.globals);
  compiler_mark_roots();
  object_mark((Object *)vm.string_init);
}

static void array_mark(ValueArray *array) {
  for (int i = 0; i < array->count; i++) {
    value_mark(array->values[i]);
  }
}

static void object_blacken(Object *object) {
#ifdef DEBUG_LOG_GC
  printf("%p blacken ", (void *)object);
  value_print(OBJECT(object));
  printf("\n");
#endif
  switch (object->type) {
    case OBJ_CLASS: {
      Class *class = (Class *)object;
      object_mark((Object *)class->name);
      table_mark(&class->methods);
      break;
    }
    case OBJ_CLOSURE: {
      Closure *closure = (Closure *)object;
      object_mark((Object *)closure->function);
      for (int i = 0; i < closure->upvalue_count; i++) {
        object_mark((Object *)closure->upvalues[i]);
      }
      break;
    }
    case OBJ_INSTANCE: {
      Instance *instance = (Instance *)object;
      object_mark((Object *)instance->class);
      table_mark(&instance->fields);
      break;
    }
    case OBJ_FUNCTION: {
      Function *function = (Function *)object;
      object_mark((Object *)function->name);
      array_mark(&function->chunk.constants);
      break;
    }
    case OBJ_METHOD: {
      Method *bound = (Method *)object;
      value_mark(bound->receiver);
      object_mark((Object *)bound->method);
      break;
    }
    case OBJ_NATIVE:
      break;
    case OBJ_STRING:
      break;
    case OBJ_UPVALUE:
      value_mark(((Upvalue *)object)->closed);
      break;
  }
}

static void gc_trace() {
  while (vm.gc.gray_count > 0) {
    Object *object = vm.gc.gray_stack[--vm.gc.gray_count];
    object_blacken(object);
  }
}

static void gc_sweep() {
  Object *prev = NULL;
  Object *object = vm.objects;
  while (object != NULL) {
    if (object->is_marked) {
      object->is_marked = false;
      prev = object;
      object = object->next;
    } else {
      Object *unreached = object;
      object = object->next;
      if (prev != NULL) {
        prev->next = object;
      } else {
        vm.objects = object;
      }
      object_free(unreached);
    }
  }
}

static void gc_remove_white(Table *table) {
  for (int i = 0; i < table->capacity; i++) {
    Entry *entry = &table->entries[i];
    if (entry->key != NULL && !entry->key->obj.is_marked) {
      table_delete(table, entry->key);
    }
  }
}

static void gc_weak() { gc_remove_white(&vm.strings); }

static void gc() {
#ifdef DEBUG_LOG_GC
  printf("-- gc begin\n");
  size_t before = vm.gc.bytes_allocated;
#endif
  gc_mark();
  gc_trace();
  gc_weak();
  gc_sweep();
  vm.gc.next_gc = vm.gc.bytes_allocated * GC_HEAP_GROW_FACTOR;
#ifdef DEBUG_LOG_GC
  printf("-- gc end\n");
  printf("   collected %ld bytes (from %ld to %ld) next at %ld\n",
         before - vm.gc.bytes_allocated, before, vm.gc.bytes_allocated,
         vm.gc.next_gc);
#endif
}

//=======================================================================//
// Native functions
//=======================================================================//

static Value native_clock(UNUSED int arg_count, UNUSED Value *args) {
  return NUMBER((double)clock() / CLOCKS_PER_SEC);
}

//=======================================================================//
// Driver
//=======================================================================//

static void driver_repl() {
  char line[1024];
  for (;;) {
    printf("> ");
    if (!fgets(line, sizeof(line), stdin)) {
      printf("\n");
      break;
    }
    vm_interpret(line);
  }
}

static char *driver_read_file(const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "Could not open file \"%s\".\n", path);
    exit(74);
  }

  fseek(file, 0L, SEEK_END);
  size_t file_size = ftell(file);
  rewind(file);

  char *buffer = (char *)malloc(file_size + 1);
  if (buffer == NULL) {
    fprintf(stderr, "Not enough memory to read \"%s\".\n", path);
    exit(74);
  }

  size_t bytes_read = fread(buffer, sizeof(char), file_size, file);
  if (bytes_read < file_size) {
    fprintf(stderr, "Could not read file \"%s\".\n", path);
    exit(74);
  }

  buffer[bytes_read] = '\0';
  fclose(file);
  return buffer;
}

static void driver_run_file(const char *path) {
  char *source = driver_read_file(path);
  InterpretResult result = vm_interpret(source);
  free(source);

  if (result == INTERPRET_COMPILE_ERROR) exit(65);
  if (result == INTERPRET_RUNTIME_ERROR) exit(70);
}

int main(int argc, char **argv) {
  vm_init();

  if (argc == 1) {
    driver_repl();
  } else if (argc == 2) {
    driver_run_file(argv[1]);
  } else {
    fprintf(stderr, "Usage: clox [path]\n");
    return -1;
  }

  vm_free();
}
