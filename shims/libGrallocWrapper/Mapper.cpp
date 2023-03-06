/*
 * Copyright (C) 2018 Lukas Berger
 * Copyright (C) 2023 Enes Murat Uzun
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "libGrallocWrapper"
// #define LOG_NDEBUG 0

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hardware/gralloc.h>
#include <ion/ion.h>

#include <utils/Log.h>
#include <cutils/native_handle.h>

#include "gralloc_priv.h"
#include "exynos_format.h"


#define GRALLOC_PATH  "/system/lib/hw/gralloc.exynos5.so"

#define INT_TO_PTR(var) ((void *)(unsigned long)var)

typedef int (*gralloc_map_t)(gralloc_module_t const* module, buffer_handle_t handle);

static gralloc_map_t __gralloc_map = NULL;

static void gralloc_init_dlsym(void) {
	void *dlhandle;

	if (__gralloc_map) {
		return;
	}

	dlhandle = dlopen(GRALLOC_PATH, RTLD_NOW);
	if (!dlhandle) {
		ALOGE("failed to open %s: %s", GRALLOC_PATH, dlerror());
	}

    __gralloc_map = (gralloc_map_t)dlsym(dlhandle, "_ZL11gralloc_mapPK16gralloc_module_tPK13native_handle");
    if (!__gralloc_map) {
		ALOGE("failed to link gralloc_map(): %s", dlerror());
	}
}

int gralloc_lock(gralloc_module_t const* module,
                 buffer_handle_t handle, int usage,
                 int l, int t, int w, int h,
                 void** vaddr)
{
	gralloc_init_dlsym();
    native_handle* handle2 = (native_handle*)handle;
    handle2->numInts = private_handle_t::sNumInts();
    handle2->numFds = private_handle_t::sNumFds;
    
    int ext_size = 256;

    if (private_handle_t::validate(handle2) < 0)
        return -1;

    private_handle_t* hnd = (private_handle_t*)handle2;

    if (hnd->frameworkFormat == HAL_PIXEL_FORMAT_YCbCr_420_888) {
        ALOGE("gralloc_lock can't be used with YCbCr_420_888 format");
        return -1;
    }

    if (!hnd->base)
        __gralloc_map(module, hnd);
    *vaddr = INT_TO_PTR(hnd->base);

    if (hnd->format == HAL_PIXEL_FORMAT_EXYNOS_YCbCr_420_SPN)
        vaddr[1] = (int*)vaddr[0] + (hnd->stride * hnd->vstride) + ext_size;
    else if (hnd->format == HAL_PIXEL_FORMAT_EXYNOS_YCbCr_420_SPN_S10B)
        vaddr[1] = (int*)vaddr[0] + (hnd->stride * hnd->vstride) + ext_size + (ALIGN(hnd->width / 4, 16) * hnd->vstride) + 64;

    {
        if (hnd->fd1 >= 0)
            vaddr[1] = INT_TO_PTR(hnd->base1);
        if (hnd->fd2 >= 0)
            vaddr[2] = INT_TO_PTR(hnd->base2);
    }

    return 0;
}

int getIonFd(gralloc_module_t const *module)
{
    private_module_t* m = const_cast<private_module_t*>(reinterpret_cast<const private_module_t*>(module));
    if (m->ionfd == -1)
        m->ionfd = ion_open();
    return m->ionfd;
}

int gralloc_unlock(gralloc_module_t const* module,
                   buffer_handle_t handle)
{
    native_handle* handle2 = (native_handle*)handle;
    handle2->numInts = private_handle_t::sNumInts();
    handle2->numFds = private_handle_t::sNumFds;
    
    if (private_handle_t::validate(handle) < 0)
        return -EINVAL;

    private_handle_t* hnd = (private_handle_t*)handle2;

    if (!((hnd->flags & GRALLOC_USAGE_SW_READ_MASK) == GRALLOC_USAGE_SW_READ_OFTEN))
        return 0;

    ion_sync_fd(getIonFd(module), hnd->fd);
    {
        if (hnd->fd1 >= 0)
            ion_sync_fd(getIonFd(module), hnd->fd1);
        if (hnd->fd2 >= 0)
            ion_sync_fd(getIonFd(module), hnd->fd2);
    }

    return 0;
}



