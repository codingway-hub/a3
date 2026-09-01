package ingest

import (
	"sync"
	"time"
)

// ipRateLimiter 按来源 IP 的令牌桶限流（注册接口专用）：容量与补充速率可配，
// 内存态、不跨实例（单进程部署满足需求）；限流事件由调用方落使用记录留痕。
type ipRateLimiter struct {
	mu       sync.Mutex
	capacity float64
	refill   time.Duration // 每过该时长补充一个令牌
	buckets  map[string]*rateBucket
}

type rateBucket struct {
	tokens   float64
	lastFill time.Time
}

// newIPRateLimiter 构建按 IP 限流器：capacity 为突发容量，refill 为单令牌补充间隔。
func newIPRateLimiter(capacity int, refill time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		capacity: float64(capacity),
		refill:   refill,
		buckets:  make(map[string]*rateBucket),
	}
}

// Allow 判定该 IP 是否放行；不放行时原子的消耗一个令牌。
func (limiter *ipRateLimiter) Allow(ip string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	bucket, exists := limiter.buckets[ip]
	if !exists {
		bucket = &rateBucket{tokens: limiter.capacity, lastFill: time.Now()}
		limiter.buckets[ip] = bucket
	}
	now := time.Now()
	elapsed := now.Sub(bucket.lastFill)
	fillSteps := elapsed / limiter.refill
	if fillSteps > 0 {
		bucket.tokens = min(limiter.capacity, bucket.tokens+float64(fillSteps))
		bucket.lastFill = bucket.lastFill.Add(fillSteps * limiter.refill)
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}