
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#ifndef _bjrk-edge_RWLOCK_H_INCLUDED_
#define _bjrk-edge_RWLOCK_H_INCLUDED_


#include <bjrk-edge_config.h>
#include <bjrk-edge_core.h>


void ngx_rwlock_wlock(ngx_atomic_t *lock);
void ngx_rwlock_rlock(ngx_atomic_t *lock);
void ngx_rwlock_unlock(ngx_atomic_t *lock);
void ngx_rwlock_downgrade(ngx_atomic_t *lock);


#endif /* _bjrk-edge_RWLOCK_H_INCLUDED_ */
