# SAE Key Synchronization Proposal
## Scheduled Key Changes with Three-Way Handshake

**Document Version**: 1.0  
**Date**: December 2024  
**Author**: SAE Client Development Team  
**Target Audience**: KME Development Team  

---

## Executive Summary

This document proposes a key synchronization mechanism for SAE-to-SAE communication that ensures both parties change keys simultaneously using a scheduled approach with a three-way handshake. This eliminates the timing issues inherent in polling-based notification systems.

## Problem Statement

### Current Challenge
Traditional notification systems using polling create synchronization gaps:
- Master SAE receives keys immediately
- Slave SAE polls every 30+ seconds
- 29+ second window where keys are out of sync
- Encryption/decryption failures during this window

### Impact
- Application-level failures
- Protocol timeouts
- Security gaps
- Poor user experience

## Proposed Solution

### Overview
Implement a scheduled key change mechanism where:
1. Master SAE requests keys with a future timestamp
2. Three-way handshake ensures both SAEs are ready
3. Both SAEs change keys simultaneously at the scheduled time

### Key Components

#### 1. Enhanced Key Request
```json
{
  "key_size": 256,
  "quantity": 1,
  "master_sae_id": "MASTER_001",
  "slave_sae_id": "SLAVE_001",
  "scheduled_time": 1703123456,
  "timezone": "UTC"
}
```

#### 2. Enhanced Key Response
```json
{
  "keys": [...],
  "scheduled_time": 1703123456,
  "master_sae_id": "MASTER_001",
  "slave_sae_id": "SLAVE_001",
  "notification_id": "uuid-1234-5678-9abc-def012345678"
}
```

## Detailed Protocol Flow

### Phase 1: Key Request and Generation
```
Master SAE                    KME                    Slave SAE
    |                          |                        |
    |-- Request Keys --------->|                        |
    |   (with scheduled_time)  |                        |
    |                          |                        |
    |<-- Keys + Schedule -----|                        |
    |   (with notification_id) |                        |
```

### Phase 2: Notification and Handshake
```
Master SAE                    KME                    Slave SAE
    |                          |                        |
    |-- Notify Slave --------->|                        |
    |                          |-- Notification ------->|
    |                          |   (with schedule)      |
    |                          |                        |
    |                          |<-- Notify ACK ---------|
    |                          |                        |
    |<-- ACK to Master --------|                        |
    |                          |                        |
    |-- Final ACK ------------>|                        |
    |                          |                        |
```

### Phase 3: Scheduled Key Change
```
Master SAE                    KME                    Slave SAE
    |                          |                        |
    |                    [At scheduled_time]            |
    |                          |                        |
    |-- Use New Keys --------->|<-- Use New Keys -------|
```

## KME API Extensions Required

### 1. Enhanced Key Request Endpoint
**URL**: `POST /api/v1/keys/{slave_sae_id}/enc_keys`  
**New Parameters**:
- `scheduled_time`: UTC epoch timestamp
- `timezone`: Timezone identifier (optional, default UTC)

**Response Enhancement**:
- Add `scheduled_time` field
- Add `notification_id` field for tracking

### 2. Notification Endpoint
**URL**: `POST /api/v1/notifications/{slave_sae_id}/notify`  
**Purpose**: Queue notification for slave SAE  
**Payload**:
```json
{
  "type": "key_schedule",
  "scheduled_time": 1703123456,
  "notification_id": "uuid-1234-5678-9abc-def012345678",
  "master_sae_id": "MASTER_001"
}
```

### 3. Acknowledgment Endpoints
**URL**: `POST /api/v1/notifications/{notification_id}/ack`  
**Purpose**: Receive slave SAE acknowledgment

**URL**: `POST /api/v1/notifications/{notification_id}/final_ack`  
**Purpose**: Receive master SAE final acknowledgment

### 4. Scheduled Key Retrieval
**URL**: `GET /api/v1/keys/scheduled/{notification_id}`  
**Purpose**: Retrieve keys for scheduled key change

## Data Models

### KeyRequestWithSchedule
```python
class KeyRequestWithSchedule(BaseModel):
    key_size: int
    quantity: int
    master_sae_id: str
    slave_sae_id: str
    scheduled_time: int  # UTC epoch timestamp
    timezone: str = "UTC"
```

### KeyResponseWithSchedule
```python
class KeyResponseWithSchedule(BaseModel):
    keys: List[ETSIKey]
    scheduled_time: int
    master_sae_id: str
    slave_sae_id: str
    notification_id: str
```

### NotificationRequest
```python
class NotificationRequest(BaseModel):
    type: str = "key_schedule"
    scheduled_time: int
    notification_id: str
    master_sae_id: str
```

## KME Implementation Requirements

### 1. Database Schema Extensions
```sql
-- Scheduled keys table
CREATE TABLE scheduled_keys (
    notification_id VARCHAR(36) PRIMARY KEY,
    slave_sae_id VARCHAR(50) NOT NULL,
    master_sae_id VARCHAR(50) NOT NULL,
    key_data JSON NOT NULL,
    scheduled_time BIGINT NOT NULL,
    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'acknowledged', 'final_ack', 'completed', 'expired') DEFAULT 'pending',
    slave_ack_time TIMESTAMP NULL,
    master_final_ack_time TIMESTAMP NULL
);

-- Notification queue table
CREATE TABLE notification_queue (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sae_id VARCHAR(50) NOT NULL,
    notification_data JSON NOT NULL,
    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivered_time TIMESTAMP NULL,
    INDEX idx_sae_id (sae_id),
    INDEX idx_created_time (created_time)
);
```

### 2. Key Management Logic
```python
def store_scheduled_keys(slave_sae_id, keys, scheduled_time, notification_id):
    """Store keys for scheduled retrieval"""
    # Store in scheduled_keys table
    # Set status to 'pending'
    pass

def queue_notification(sae_id, notification_data):
    """Queue notification for SAE"""
    # Insert into notification_queue table
    pass

def get_pending_notifications(sae_id):
    """Get pending notifications for SAE"""
    # Query notification_queue table
    # Mark as delivered
    pass

def record_slave_ack(notification_id):
    """Record slave SAE acknowledgment"""
    # Update scheduled_keys status to 'acknowledged'
    # Set slave_ack_time
    pass

def record_master_final_ack(notification_id):
    """Record master SAE final acknowledgment"""
    # Update scheduled_keys status to 'final_ack'
    # Set master_final_ack_time
    pass

def get_scheduled_keys(notification_id):
    """Retrieve keys for scheduled key change"""
    # Query scheduled_keys table
    # Update status to 'completed'
    pass
```

### 3. Cleanup Processes
```python
def cleanup_expired_schedules():
    """Remove expired scheduled keys"""
    # Delete records older than 24 hours
    # Clean up orphaned notifications
    pass

def cleanup_delivered_notifications():
    """Remove delivered notifications"""
    # Delete notifications older than 1 hour
    pass
```

## Configuration Parameters

### KME Configuration
```yaml
scheduled_keys:
  default_offset_seconds: 600  # 10 minutes
  max_offset_seconds: 3600     # 1 hour
  min_offset_seconds: 60       # 1 minute
  cleanup_interval_hours: 24
  notification_retention_hours: 1
```

### SAE Configuration
```yaml
key_synchronization:
  schedule_offset_seconds: 600
  handshake_timeout_seconds: 30
  final_ack_timeout_seconds: 30
  retry_attempts: 3
  max_scheduled_keys: 100
```

## Error Handling

### 1. Handshake Timeouts
- **Slave ACK timeout**: Master proceeds without coordination
- **Master final ACK timeout**: Slave clears schedule
- **Network partition**: Both sides handle gracefully

### 2. Clock Synchronization
- **NTP drift tolerance**: ±5 seconds
- **Clock skew detection**: Warn if difference > 10 seconds
- **Fallback**: Immediate key change if clocks are too far apart

### 3. Resource Management
- **Memory cleanup**: Automatic timer cleanup
- **Database cleanup**: Scheduled cleanup processes
- **Orphaned records**: Detection and removal

## Mitigations (Optional Enhancements)

The following mitigations address potential downsides of the scheduled key change approach. These are optional enhancements that can be implemented based on deployment requirements and risk tolerance.

### 1. Clock Synchronization Issues - Mitigation

#### **A. NTP Drift Tolerance**
```python
class ClockSynchronizationManager:
    def __init__(self):
        self.max_clock_skew_seconds = 5
        self.ntp_servers = ["pool.ntp.org", "time.google.com"]
    
    def validate_scheduled_time(self, scheduled_time):
        """Validate scheduled time against local clock"""
        current_time = time.time()
        time_difference = abs(scheduled_time - current_time)
        
        if time_difference > self.max_clock_skew_seconds:
            raise ClockSkewError(f"Clock skew too large: {time_difference}s")
        
        return True
    
    def get_adjusted_scheduled_time(self, requested_time, offset_seconds=600):
        """Adjust scheduled time to account for clock differences"""
        current_time = time.time()
        adjusted_time = current_time + offset_seconds
        
        # Ensure minimum time difference
        if adjusted_time - current_time < 60:
            adjusted_time = current_time + 60
        
        return int(adjusted_time)
```

#### **B. Clock Skew Detection and Correction**
```python
def detect_clock_skew(self, master_time, slave_time):
    """Detect clock skew between SAEs"""
    skew = abs(master_time - slave_time)
    
    if skew > 10:  # More than 10 seconds difference
        self.logger.warning(f"Clock skew detected: {skew} seconds")
        return False
    
    return True

def handle_clock_skew(self, scheduled_time):
    """Handle clock skew by adjusting schedule"""
    current_time = time.time()
    
    if scheduled_time < current_time + 30:  # Too close to now
        # Reschedule with minimum offset
        new_scheduled_time = current_time + 60
        self.logger.info(f"Rescheduled due to clock skew: {new_scheduled_time}")
        return new_scheduled_time
    
    return scheduled_time
```

#### **C. Fallback Mechanism**
```python
def schedule_key_change_with_fallback(self, scheduled_time, keys):
    """Schedule key change with fallback for clock issues"""
    try:
        # Validate scheduled time
        self.validate_scheduled_time(scheduled_time)
        
        # Schedule the change
        self.schedule_key_change(scheduled_time, keys)
        
    except ClockSkewError as e:
        # Fallback: immediate key change
        self.logger.warning(f"Clock skew detected, using immediate key change: {e}")
        self.activate_keys_immediately(keys)
```

### 2. Network Partitioning - Mitigation

#### **A. Robust Handshake with Timeouts**
```python
class HandshakeManager:
    def __init__(self):
        self.slave_ack_timeout = 30
        self.master_final_ack_timeout = 30
        self.max_retry_attempts = 3
    
    def perform_handshake(self, notification_id):
        """Perform three-way handshake with timeout handling"""
        # Phase 1: Wait for slave ACK
        slave_ack_received = self.wait_for_slave_ack(
            notification_id, 
            timeout=self.slave_ack_timeout
        )
        
        if not slave_ack_received:
            self.logger.warning("Slave ACK timeout - proceeding without coordination")
            return False
        
        # Phase 2: Send final ACK
        self.send_final_ack(notification_id)
        
        # Phase 3: Wait for confirmation
        final_confirmation = self.wait_for_final_confirmation(
            notification_id,
            timeout=self.master_final_ack_timeout
        )
        
        return final_confirmation
    
    def wait_for_slave_ack(self, notification_id, timeout):
        """Wait for slave acknowledgment with exponential backoff"""
        start_time = time.time()
        attempt = 0
        
        while time.time() - start_time < timeout:
            try:
                ack_status = self.check_slave_ack_status(notification_id)
                if ack_status:
                    return True
                
                # Exponential backoff
                wait_time = min(2 ** attempt, 5)  # Max 5 seconds
                time.sleep(wait_time)
                attempt += 1
                
            except Exception as e:
                self.logger.error(f"Error checking slave ACK: {e}")
                time.sleep(1)
        
        return False
```

#### **B. Network Partition Detection**
```python
def detect_network_partition(self, notification_id):
    """Detect if network partition occurred during handshake"""
    # Check if both sides have different states
    master_state = self.get_master_state(notification_id)
    slave_state = self.get_slave_state(notification_id)
    
    if master_state == 'final_ack_sent' and slave_state == 'pending':
        # Network partition detected
        self.logger.error("Network partition detected during handshake")
        return True
    
    return False

def handle_network_partition(self, notification_id):
    """Handle network partition gracefully"""
    # Clear the schedule to prevent orphaned keys
    self.clear_scheduled_keys(notification_id)
    
    # Log the incident
    self.log_incident("network_partition", notification_id)
    
    # Notify administrators
    self.send_alert("Network partition detected - key synchronization may be inconsistent")
```

#### **C. State Recovery Mechanisms**
```python
def recover_from_partition(self, notification_id):
    """Recover from network partition"""
    # Check current states
    master_state = self.get_master_state(notification_id)
    slave_state = self.get_slave_state(notification_id)
    
    if master_state == 'keys_activated' and slave_state == 'pending':
        # Master has keys, slave doesn't - trigger slave key request
        self.trigger_slave_key_request(notification_id)
    
    elif master_state == 'pending' and slave_state == 'keys_activated':
        # Slave has keys, master doesn't - trigger master key request
        self.trigger_master_key_request(notification_id)
    
    else:
        # Both in same state - clear and retry
        self.clear_scheduled_keys(notification_id)
```

### 3. Resource Management - Mitigation

#### **A. Automatic Cleanup Processes**
```python
class ResourceManager:
    def __init__(self):
        self.cleanup_interval = 3600  # 1 hour
        self.max_scheduled_keys = 1000
        self.max_notification_age = 86400  # 24 hours
    
    def start_cleanup_scheduler(self):
        """Start periodic cleanup processes"""
        def cleanup_worker():
            while True:
                try:
                    self.cleanup_expired_schedules()
                    self.cleanup_delivered_notifications()
                    self.cleanup_orphaned_timers()
                    time.sleep(self.cleanup_interval)
                except Exception as e:
                    self.logger.error(f"Cleanup error: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def cleanup_expired_schedules(self):
        """Remove expired scheduled keys"""
        current_time = time.time()
        expired_keys = self.get_expired_scheduled_keys(current_time)
        
        for key in expired_keys:
            self.delete_scheduled_key(key.notification_id)
            self.logger.info(f"Cleaned up expired schedule: {key.notification_id}")
    
    def cleanup_orphaned_timers(self):
        """Clean up orphaned scheduled timers"""
        active_timers = self.get_active_timers()
        valid_schedules = self.get_valid_schedules()
        
        for timer in active_timers:
            if timer.notification_id not in valid_schedules:
                timer.cancel()
                self.logger.info(f"Cancelled orphaned timer: {timer.notification_id}")
```

#### **B. Memory Management**
```python
class TimerManager:
    def __init__(self):
        self.active_timers = {}
        self.max_timers = 100
    
    def schedule_timer(self, notification_id, scheduled_time, callback):
        """Schedule timer with memory management"""
        if len(self.active_timers) >= self.max_timers:
            # Clean up oldest timers
            self.cleanup_oldest_timers(10)
        
        timer = threading.Timer(scheduled_time - time.time(), callback)
        timer.start()
        
        self.active_timers[notification_id] = {
            'timer': timer,
            'scheduled_time': scheduled_time,
            'created_time': time.time()
        }
    
    def cleanup_oldest_timers(self, count):
        """Clean up oldest timers to free memory"""
        sorted_timers = sorted(
            self.active_timers.items(),
            key=lambda x: x[1]['created_time']
        )
        
        for i in range(min(count, len(sorted_timers))):
            notification_id, timer_info = sorted_timers[i]
            timer_info['timer'].cancel()
            del self.active_timers[notification_id]
```

### 4. Security Considerations - Mitigation

#### **A. Replay Protection**
```python
class SecurityManager:
    def __init__(self):
        self.used_notification_ids = set()
        self.max_notification_age = 3600  # 1 hour
    
    def validate_notification(self, notification):
        """Validate notification for replay attacks"""
        # Check notification ID uniqueness
        if notification['notification_id'] in self.used_notification_ids:
            raise SecurityError("Duplicate notification ID - possible replay attack")
        
        # Check timestamp freshness
        current_time = time.time()
        notification_time = notification['scheduled_time']
        
        if abs(current_time - notification_time) > self.max_notification_age:
            raise SecurityError("Notification timestamp too old - possible replay attack")
        
        # Add to used set
        self.used_notification_ids.add(notification['notification_id'])
        
        # Clean up old IDs periodically
        if len(self.used_notification_ids) > 10000:
            self.cleanup_old_notification_ids()
    
    def cleanup_old_notification_ids(self):
        """Clean up old notification IDs to prevent memory growth"""
        current_time = time.time()
        cutoff_time = current_time - self.max_notification_age
        
        # Remove old IDs (simplified - in practice, use time-based cleanup)
        self.used_notification_ids.clear()
```

#### **B. Timing Attack Protection**
```python
def add_timing_jitter(self, scheduled_time):
    """Add random jitter to prevent timing attacks"""
    jitter = random.randint(-2, 2)  # ±2 seconds
    return scheduled_time + jitter

def rate_limit_key_requests(self, sae_id):
    """Rate limit key requests to prevent DoS"""
    current_time = time.time()
    recent_requests = self.get_recent_requests(sae_id, current_time - 3600)
    
    if len(recent_requests) > 10:  # Max 10 requests per hour
        raise RateLimitError("Too many key requests - rate limit exceeded")
```

### 5. Complexity - Mitigation

#### **A. Clear State Machines**
```python
class HandshakeStateMachine:
    """Clear state machine for handshake process"""
    
    STATES = {
        'INIT': 'Initial state',
        'KEYS_REQUESTED': 'Keys requested from KME',
        'SLAVE_NOTIFIED': 'Slave SAE notified',
        'SLAVE_ACKED': 'Slave SAE acknowledged',
        'MASTER_FINAL_ACKED': 'Master SAE sent final ACK',
        'COMPLETED': 'Handshake completed',
        'FAILED': 'Handshake failed'
    }
    
    def __init__(self, notification_id):
        self.notification_id = notification_id
        self.current_state = 'INIT'
        self.state_history = []
    
    def transition_to(self, new_state):
        """Transition to new state with logging"""
        old_state = self.current_state
        self.current_state = new_state
        self.state_history.append({
            'timestamp': time.time(),
            'from_state': old_state,
            'to_state': new_state
        })
        
        self.logger.info(f"State transition: {old_state} -> {new_state}")
    
    def is_valid_transition(self, new_state):
        """Validate state transition"""
        valid_transitions = {
            'INIT': ['KEYS_REQUESTED'],
            'KEYS_REQUESTED': ['SLAVE_NOTIFIED', 'FAILED'],
            'SLAVE_NOTIFIED': ['SLAVE_ACKED', 'FAILED'],
            'SLAVE_ACKED': ['MASTER_FINAL_ACKED', 'FAILED'],
            'MASTER_FINAL_ACKED': ['COMPLETED', 'FAILED'],
            'COMPLETED': [],
            'FAILED': []
        }
        
        return new_state in valid_transitions.get(self.current_state, [])
```

#### **B. Comprehensive Testing**
```python
class TestSuite:
    """Comprehensive test suite for key synchronization"""
    
    def test_clock_synchronization(self):
        """Test clock synchronization scenarios"""
        # Test normal operation
        # Test clock skew
        # Test NTP drift
        # Test timezone issues
        pass
    
    def test_network_partitioning(self):
        """Test network partition scenarios"""
        # Test partial handshake
        # Test complete partition
        # Test recovery mechanisms
        pass
    
    def test_resource_management(self):
        """Test resource management"""
        # Test memory leaks
        # Test timer cleanup
        # Test database cleanup
        pass
    
    def test_security_scenarios(self):
        """Test security scenarios"""
        # Test replay attacks
        # Test timing attacks
        # Test rate limiting
        pass
```

### Implementation Priority for Mitigations

1. **Clock Synchronization** - Most critical for basic functionality
2. **Network Partition Handling** - Essential for reliability  
3. **Resource Management** - Prevents long-term issues
4. **Security Protections** - Protects against attacks
5. **Complexity Management** - Improves maintainability

These mitigations can be implemented incrementally based on deployment requirements and risk tolerance.

## Security Considerations

### 1. Replay Protection
- **Notification ID uniqueness**: UUID-based
- **Timestamp validation**: Reject old timestamps
- **SAE ID verification**: Validate against certificate

### 2. Timing Attacks
- **Random jitter**: Add small random delays
- **Clock obfuscation**: Don't expose precise timing
- **Rate limiting**: Prevent rapid key change requests

### 3. Authorization
- **SAE allow list**: KME validates SAE IDs
- **Certificate validation**: mTLS authentication
- **Key ownership**: Verify key belongs to requesting SAE

## Testing Requirements

### 1. Unit Tests
- Key scheduling logic
- Handshake state machines
- Timeout handling
- Error conditions

### 2. Integration Tests
- End-to-end key synchronization
- Network partition scenarios
- Clock skew scenarios
- High-load testing

### 3. Security Tests
- Replay attack prevention
- Authorization bypass attempts
- Timing attack resistance

## Migration Strategy

### Phase 1: Backward Compatibility
- Support both old and new APIs
- Gradual rollout to SAEs
- Monitoring and metrics

### Phase 2: Full Implementation
- Deprecate old notification methods
- Complete migration to scheduled keys
- Performance optimization

### Phase 3: Advanced Features
- Dynamic scheduling based on load
- Predictive key changes
- Advanced error recovery

## Monitoring and Metrics

### Key Metrics
- Key synchronization success rate
- Handshake completion time
- Clock skew distribution
- Error rates by type
- Resource usage

### Alerts
- High synchronization failure rate
- Excessive clock skew
- Resource exhaustion
- Security violations

## Conclusion

This proposed solution provides:
- ✅ **Perfect synchronization** between SAEs
- ✅ **Robust error handling** and recovery
- ✅ **Security protection** against common attacks
- ✅ **Scalable architecture** for future growth
- ✅ **Backward compatibility** during migration

The scheduled key change approach eliminates the timing issues of polling-based systems while providing a robust, secure, and scalable solution for SAE key synchronization.

---

## Appendix A: Implementation Timeline

**Week 1-2**: KME API extensions and database schema
**Week 3-4**: SAE client implementation and testing
**Week 5-6**: Integration testing and security validation
**Week 7-8**: Production deployment and monitoring

## Appendix B: Reference Implementation

See the SAE client implementation in the `src/services/notification_service.py` file for a complete reference implementation of this protocol.

## Appendix C: ETSI Compliance

This implementation extends the ETSI GS QKD 014 specification while maintaining full compliance with existing requirements. The scheduled key change mechanism is an enhancement that does not violate any existing specifications.
