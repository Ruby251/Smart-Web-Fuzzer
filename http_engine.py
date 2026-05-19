import asyncio
import aiohttp
from typing import Dict, Any, Optional
import time
from collections import deque
import random

class RateLimiter:
    def __init__(self, max_requests: int = 100, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        
    async def acquire(self):
        now = time.time()
        while self.requests and self.requests[0] < now - self.time_window:
            self.requests.popleft()
            
        if len(self.requests) >= self.max_requests:
            sleep_time = self.time_window - (now - self.requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                
        self.requests.append(now)


class HttpEngine:
    def __init__(self, timeout: int = 10, max_retries: int = 3, rate_limit: int = 50):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limiter = RateLimiter(max_requests=rate_limit)
        self.session = None
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=200,
            ttl_dns_cache=300,
            ssl=False
        )
        self.session = aiohttp.ClientSession(connector=connector)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def request(self, url: str, method: str = 'GET', 
                     params: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     cookies: Optional[Dict] = None) -> Dict[str, Any]:
        
        await self.rate_limiter.acquire()
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                async with self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers or {},
                    data=data,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True
                ) as response:
                    
                    response_time = (time.time() - start_time) * 1000
                    text = await response.text()
                    
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'text': text,
                        'response_time': response_time,
                        'url': str(response.url)
                    }
                    
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return {'error': 'timeout', 'status': 0}
                await asyncio.sleep(0.5 * (2 ** attempt))
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return {'error': str(e), 'status': 0}
                await asyncio.sleep(0.5)
                
        return {'error': 'max_retries_exceeded', 'status': 0}