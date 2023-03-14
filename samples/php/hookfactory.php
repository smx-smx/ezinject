<?php
/**
 * Copyright (C) 2023 Stefano Moioli <smxdev@gmail.com>
 * 
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * 
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 
 *     1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *     2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *     3. This notice may not be removed or altered from any source distribution.
 * 
 **/

use FFI\CData;

interface HookFactory {
	public function makePfn(string $type, $closure);
	public function newHook(string $type, string $funcName, callable $hook);
}

class HookHandle {
	private Closure $wrapCb;
	private Closure $hookCb;
	private CData $nat;

	public function __construct(HookFactory $parent, string $type, CData $pfnOrig, callable $hookCb){
		$this->wrapCb = Closure::fromCallable(function(...$args) use($pfnOrig, $hookCb){
			return $hookCb($pfnOrig, ...$args);
		});
		$this->nat = $parent->makePfn($type, $this->wrapCb);
	}

	public function getNativeHandle(){
		return $this->nat;
	}
}

class HookFactoryFrida implements HookFactory {
	private static bool $initialized = false;

	private FFI $ffi;
	private CData $self;

	private CData $gum;

	/**
	 * @var HookHandle[]
	 */
	private array $handles = array();

	public function __construct(string $extra_decl="") {
		$this->ffi = FFI::cdef("
			void gum_init ();
			void *gum_interceptor_obtain();
			void gum_interceptor_begin_transaction(void *handle);
			int gum_interceptor_replace (void *handle, 
				void *function_address, 
				void *replacement_function,
				void *replacement_data);
			void gum_interceptor_end_transaction(void *handle);
			
			void *dlopen(const char *filename, int flag);
			void *dlsym(void *handle, const char *symbol);
		" . $extra_decl);
		$this->self = $this->ffi->dlopen(NULL, 0x01);
		if($this->self == null){
			throw new \Exception("dlopen self failed");
		}

		if(!self::$initialized){
			$this->ffi->gum_init();
			self::$initialized = true;
		}
		$this->gum = $this->ffi->gum_interceptor_obtain();
	}

	/**
	 * converts a closure or an interger into a typed function pointer
	 */
	public function makePfn(string $type, $closure){
		$fnT = $this->ffi->type($type);
		$arrT = FFI::arrayType($fnT, [1]);
		$arr = FFI::new($arrT);
		$arr[0] = $closure;
		return $arr[0];
    }

    public function hasSymbol(string $funcName) {
        return $this->ffi->dlsym($this->self, $funcName) != null;
    }

	public function newHook(string $type, string $funcName, callable $hook){
		$pvCode = $this->ffi->dlsym($this->self, $funcName);
        if($pvCode == null){
            return null;
		}

        $pfnOrig = $this->makePfn($type, $pvCode);
        $handle = new HookHandle($this, $type, $pfnOrig, $hook);

		$pvHook = $handle->getNativeHandle();
		$this->ffi->gum_interceptor_replace($this->gum,
			$pvCode, $pvHook, NULL);

		$this->handles[] = $handle;
		return $handle;
	}
}

class HookFactoryLibHooker implements HookFactory {
	private FFI $ffi;
	private CData $self;

	/**
	 * @var HookHandle[]
	 */
    private array $handles = array();

	public function __construct(string $extra_decl=""){
		$this->ffi = FFI::cdef("
			void *inj_backup_function(void *original_code, size_t *num_saved_bytes, int opcode_bytes_to_restore);
			int inj_replace_function(void *original_fn, void *replacement_fn);
			void *dlopen(const char *filename, int flag);
			void *dlsym(void *handle, const char *symbol);
		" . $extra_decl);
		$this->self = $this->ffi->dlopen(NULL, 0x01);
		if($this->self == null){
			throw new \Exception("dlopen self failed");
		}
	}

	/**
	 * converts a closure or an integer into a typed function pointer
	 */
	public function makePfn(string $type, $closure){
		$fnT = $this->ffi->type($type);
		$arrT = FFI::arrayType($fnT, [1]);
		$arr = FFI::new($arrT);
		$arr[0] = $closure;
		return $arr[0];
    }

	public function newHook(string $type, string $funcName, callable $hook){
		$pvCode = $this->ffi->dlsym($this->self, $funcName);
		if($pvCode == null){
			return null;
		}

		$pvOrig = $this->ffi->inj_backup_function($pvCode, NULL, -1);
		$pfnOrig = self::makePfn($type, $pvOrig);

		$handle = new HookHandle($type, $pfnOrig, $hook);
		$this->ffi->inj_replace_function($pvCode, $handle->getNativeHandle());

		$this->handles[] = $handle;
		return $handle;
	}
}
