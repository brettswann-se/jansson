/*
 * Copyright (c) 2009-2016 Petri Lehtinen <petri@digip.org>
 * Copyright (c) 2011-2012 Basile Starynkevitch <basile@starynkevitch.net>
 *
 * Jansson is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "jansson.h"
#include "jansson_private.h"

/* C89 allows these to be macros */
#undef malloc
#undef free

/* internal functions to wrap the use of malloc/free, ignoring the allocator arg */
static void *malloc_wrapper(json_allocator_t allocator, size_t size);
static void free_wrapper(json_allocator_t allocator, void *ptr);

/* memory function pointers */
static json_malloc_t do_malloc = malloc_wrapper;
static json_free_t do_free = free_wrapper;

static void *malloc_wrapper(json_allocator_t allocator, size_t size)
{
    (void)allocator;
    return malloc(size);
}

static void free_wrapper(json_allocator_t allocator, void *ptr)
{
    (void)allocator;
    free(ptr);
}

void *jsonp_malloc(json_allocator_t allocator, size_t size) {
    if (!size)
        return NULL;

    return (*do_malloc)(NULL, size);
}

void jsonp_free(json_allocator_t allocator, void *ptr) {
    if (!ptr)
        return;

    (*do_free)(NULL, ptr);
}

char *jsonp_strdup(const char *str) { return jsonp_strndup(str, strlen(str)); }

char *jsonp_strndup(const char *str, size_t len) {
    char *new_str;

    new_str = jsonp_malloc(NULL, len + 1);
    if (!new_str)
        return NULL;

    memcpy(new_str, str, len);
    new_str[len] = '\0';
    return new_str;
}

void json_set_alloc_funcs(json_malloc_t malloc_fn, json_free_t free_fn) {
    do_malloc = malloc_fn;
    do_free = free_fn;
}

void json_get_alloc_funcs(json_malloc_t *malloc_fn, json_free_t *free_fn) {
    if (malloc_fn)
        *malloc_fn = do_malloc;
    if (free_fn)
        *free_fn = do_free;
}
