# DTU 02244 Logic for Security
## Project on Information Flow


## 1 System Participants & Roles

This section defines all actors in the system, with consistent role mapping to our Assignment 1 OpenAuth protocol, and clear authority boundaries for information flow control (IFC). All actors are authenticated via the trusted Identity Provider (IdP) reused from Assignment 1, with no unauthenticated access to the server. The IdP acts only as a root of trust for identity authentication, with no ownership or access rights to user data, and no participation in IFC rule enforcement.

1.  **Data Owner (O)**
    - Core identity: End user of the hosting service, the sole legal owner of all data they upload to the server (corresponds to Agent A in Assignment 1).
    - IFC authorities: Defines security labels for all owned data, grants/revokes cross-user access to data, uploads programs for execution on owned data, and is the only actor authorized to declassify owned data.
    - Core responsibility: Initiates all authorization flows via the IdP, per the OpenAuth protocol from Assignment 1.

2.  **Hosting Server (S)**
    - Core identity: The secure server designed in this report, the only entity that stores user data, enforces IFC rules, and executes programs (corresponds to Agent B in Assignment 1).
    - IFC authorities: Validates all user operations against the security lattice and label rules, performs static information flow analysis on user-uploaded programs, executes approved programs in isolated sandboxes, and maintains an immutable audit log of all operations.
    - Core responsibility: Enforces the system’s security policy for all operations, ensuring no illegal information flow even with dishonest users and malicious code.

3.  **Authorized Executor (E)**
    - Core identity: A third-party service or user authorized by the Data Owner to execute programs on specified labeled data (corresponds to Agent P in Assignment 1).
    - IFC authorities: May only access data explicitly granted by the Data Owner via the label’s effective reader set, and may only execute programs pre-approved by the Data Owner and the server’s static analysis.
    - Core responsibility: Acts only within the scope of the OpenAuth authorization token issued by the IdP and signed by the Data Owner.

4.  **Identity Provider (IdP)**
    - Core identity: The global trusted third party reused from Assignment 1, the only fully trusted entity in the system.
    - IFC authorities: Authenticates all actor identities, issues and signs authorization tokens, distributes verified public keys for all actors, and validates the freshness of all protocol interactions.
    - Core responsibility: Provides the root of trust for all identity and authorization checks in the system.

---

## 2 Formal Security Model & Security Goals

All models in this section are strictly derived from the three required course papers and the course lecture materials, with no custom modifications beyond adapting to our system's actor model.

### 2.1 Security Lattice Formalization
We follow the **security policy framework** definition from Lecture 2: a security lattice is a 4-tuple \((S, \sqsubseteq, \sqcup, \sqcap)\) that satisfies:
1.  \(S\) is a finite non-empty set of security labels;
2.  \(\sqsubseteq\) is a partial order (reflexive, transitive, anti-symmetric) over \(S\);
3.  \(\sqcup\) (join/supremum) and \(\sqcap\) (meet/infimum) are binary operations over \(S\) that satisfy the lattice axioms.

#### 2.1.1 Confidentiality Lattice (Denning & Denning, 1977)
We define a fixed global confidentiality lattice \( \mathcal{L}_C = (SC, \leq_C, \sqcup_C, \sqcap_C) \), where:
- Security class set: \( SC = \{Public, Friends, Private, TopSecret\} \)
- Partial order: \( Public \leq_C Friends \leq_C Private \leq_C TopSecret \) (higher class = stricter confidentiality)
- Join operation: \( a \sqcup_C b = \max(a,b) \) (upper bound of two classes)
- Meet operation: \( a \sqcap_C b = \min(a,b) \) (lower bound of two classes)

For any explicit or implicit information flow \( x \rightsquigarrow y \), the flow is legal if and only if \( label_C(x) \leq_C label_C(y) \).

#### 2.1.2 Integrity Lattice (Denning & Denning, 1977)
We define a dual integrity lattice \( \mathcal{L}_I = (SI, \leq_I, \sqcup_I, \sqcap_I) \), where:
- Security class set: \( SI = \{LowIntegrity, MediumIntegrity, HighIntegrity\} \)
- Partial order: \( LowIntegrity \leq_I MediumIntegrity \leq_I HighIntegrity \) (higher class = stronger trustworthiness)
- Join operation: \( a \sqcup_I b = \max(a,b) \)
- Meet operation: \( a \sqcap_I b = \min(a,b) \)

For any explicit or implicit information flow \( x \rightsquigarrow y \), the flow is legal if and only if \( label_I(y) \leq_I label_I(x) \) (low-integrity data cannot contaminate high-integrity objects).

#### 2.1.3 Product Lattice (Lecture 2)
To enforce both confidentiality and integrity simultaneously, we use the standard product lattice construction:
\[ \mathcal{L} = \mathcal{L}_C \times \mathcal{L}_I \]
with partial order:
\[ (sc_1, si_1) \leq (sc_2, si_2) \iff sc_1 \leq_C sc_2 \land si_2 \leq_I si_1 \]
All system operations must comply with this product lattice rule.

### 2.2 Decentralized Label Model (Myers & Liskov, 1997, Lecture 3)
We strictly follow the DLM from Lecture 3 for owner-centric label governance and declassification.

#### 2.2.1 Confidentiality DLM Label
A confidentiality label is a partial mapping from owners to reader sets:
\[ s = \{ o_1: R_1, o_2: R_2, ..., o_n: R_n \} \]
where:
- \( Owners(s) = \{o_1, o_2, ..., o_n\} \): the set of owners of the data;
- \( Readers(s, o) = R_o \) if \( o \in Owners(s) \), otherwise \( Readers(s, o) = P \) (all principals);
- \( EffectiveReaders(s) = \bigcap_{o \in Owners(s)} Readers(s, o) \): the only principals authorized to read the data.

**Label Partial Order**: For two labels \( s_1, s_2 \):
\[ s_1 \sqsubseteq s_2 \iff Owners(s_1) \subseteq Owners(s_2) \land \forall o \in Owners(s_1): Readers(s_1, o) \supseteq Readers(s_2, o) \]

**Join/Meet Operations**:
- \( s_1 \sqcup s_2 \): \( Owners(s_1 \sqcup s_2) = Owners(s_1) \cup Owners(s_2) \), \( Readers(s_1 \sqcup s_2, o) = Readers(s_1, o) \cap Readers(s_2, o) \)
- \( s_1 \sqcap s_2 \): \( Owners(s_1 \sqcap s_2) = Owners(s_1) \cap Owners(s_2) \), \( Readers(s_1 \sqcap s_2, o) = Readers(s_1, o) \cup Readers(s_2, o) \)

#### 2.2.2 Integrity DLM Label
An integrity label is a partial mapping from owners to writer sets:
\[ s = \{ o_1: W_1, o_2: W_2, ..., o_n: W_n \} \]
where:
- \( Writers(s, o) = W_o \) if \( o \in Owners(s) \), otherwise \( Writers(s, o) = P \);
- \( EffectiveWriters(s) = \bigcap_{o \in Owners(s)} Writers(s, o) \): the only principals authorized to modify the data.

**Label Partial Order**: For two integrity labels \( s_1, s_2 \):
\[ s_1 \sqsubseteq s_2 \iff Owners(s_1) \supseteq Owners(s_2) \land \forall o \in Owners(s_2): Writers(s_1, o) \subseteq Writers(s_2, o) \]

### 2.3 Volpano Type System (Lecture 2)
We use the sound type system from Volpano et al. (1996) for static analysis of user-uploaded programs. Security classes are treated as types, and the lattice partial order as a subtype relation.

#### Core Typing Rules
We use a type environment \( \gamma \), which maps each program variable to its security type (from our product lattice).
1.  **Constant Rule (CONST)**: \( \gamma \vdash n: \tau \) for any integer constant \( n \) and type \( \tau \)
2.  **Variable Rule (VAR)**: \( \frac{}{\gamma \vdash x: \tau} \gamma(x) \sqsubseteq \tau \)
3.  **Arithmetic/Boolean Rule (ARITH)**: \( \frac{\gamma \vdash e: \tau \quad \gamma \vdash e': \tau}{\gamma \vdash e \text{ op } e': \tau} \)
4.  **Assignment Rule (ASSIGN)**: \( \frac{\gamma \vdash e: \tau}{\gamma \vdash x:=e: \tau'} \gamma(x) = \tau, \tau' \sqsubseteq \tau \)
5.  **If Rule (IF)**: \( \frac{\gamma \vdash e: \tau \quad \gamma \vdash c_1: \tau \quad \gamma \vdash c_2: \tau}{\gamma \vdash \text{if } e \text{ then } c_1 \text{ else } c_2: \tau'} \tau' \sqsubseteq \tau \)
6.  **While Rule (WHILE)**: \( \frac{\gamma \vdash e: \tau \quad \gamma \vdash c: \tau}{\gamma \vdash \text{while } e \text{ do } c: \tau'} \tau' \sqsubseteq \tau \)
7.  **Array Access Rule (Lecture 2)**: \( \frac{}{\gamma \vdash A[e_1]: \tau} \gamma(A) \sqcup \gamma(e_1) \sqsubseteq \tau \)
8.  **Array Assignment Rule (Lecture 2)**: \( \frac{}{\gamma \vdash A[e_1] := e_2: \tau} \gamma(e_1) \sqcup \gamma(e_2) \sqsubseteq \gamma(A), \tau \sqsubseteq \gamma(A) \)

#### Non-Interference Theorem (Lecture 2)
The core guarantee of this type system is **non-interference**:
> If a program \( c \) is type-well-formed (\( \gamma \vdash c: \tau \) for any \( \tau \)), then for any two memories \( \mu_1, \mu_2 \) that are equal on all variables with type \( \sqsubseteq \tau_0 \), the resulting memories after executing \( c \) will also be equal on all variables with type \( \sqsubseteq \tau_0 \).

This means changes to high-security inputs cannot be observed in low-security outputs, eliminating all illegal explicit and implicit information flows.

### 2.4 Formal Security Goals
1.  **Confidentiality Goal**: No explicit or implicit information flow violates the product lattice's confidentiality rules. High-confidentiality data can never be accessed by unauthorized principals, even via malicious program execution.
2.  **Integrity Goal**: No explicit or implicit information flow violates the product lattice's integrity rules. High-integrity data can never be modified by unauthorized principals or contaminated by low-integrity data.
3.  **Declassification Compliance Goal**: All declassification operations are strictly initiated by the data owner, comply with the DLM rules, and are fully auditable.
4.  **Non-Interference Goal**: All user-uploaded programs approved for execution satisfy non-interference, ensuring no illegal information flows during program execution.

---

## 3 Design Choices & Reasoning


This section explains our core design choices, with explicit reasoning for how each choice achieves the security goals defined in Section 2, using only concepts from the three required course papers and lecture materials. All choices follow the assignment’s core priority: a precise, provably secure design over excessive feature scope.

### 3.1 Fixed Global Product Lattice
- **Choice**: We use a fixed global product lattice for confidentiality and integrity, rather than allowing fully user-defined lattices.
- **Reasoning**: A fixed lattice simplifies formal security proofs, ensures consistent enforcement of IFC rules across all users, and eliminates the risk of incompatible user-defined lattices introducing illegal cross-user information flows. The lattice structure is fully aligned with Denning & Denning (1977)’s foundational lattice model, and covers all common use cases (personal photo hosting, medical data management) defined in the assignment.

### 3.2 DLM Model for Owner-Centric Access Control
- **Choice**: We adopt the DLM model from Myers & Liskov (1997) for label management and access control.
- **Reasoning**: The DLM model is the only approved framework for declassification in the assignment, and it aligns perfectly with the assignment’s requirement for user-controlled data sharing. The model’s owner-centric label governance ensures that only the Data Owner can modify access rules or declassify data, directly achieving our confidentiality and integrity goals. It also integrates seamlessly with the OpenAuth authorization protocol from Assignment 1, ensuring backward compatibility.

### 3.3 Volpano Type System for Static Program Analysis
- **Choice**: We use the sound type system from Volpano et al. (1996) for **pure static analysis** of user-uploaded white-box programs, with no runtime information flow monitoring.
- **Reasoning**:
  1.  The type system provides a formal guarantee of non-interference for type-well-formed programs, which is the only way to ensure that untrusted user-uploaded code cannot leak high-confidentiality data via explicit or implicit flows.
  2.  Per Lecture 4, runtime monitoring cannot safely handle implicit flows: stopping execution due to an illegal flow creates an observable side channel that leaks sensitive information. Static analysis eliminates this risk by verifying all flows before execution.
  3.  This directly addresses the assignment’s core challenge of executing untrusted programs without violating the security policy.

### 3.4 Dual Program Execution Model
- **Choice**: We support two program execution models:
  1.  **White-box Model**: User uploads source code, server performs static type checking before execution;
  2.  **Black-box Model**: Pre-approved system functions, with security enforced via the lattice rule that the output label is the upper bound of all input labels.
- **Reasoning**: The white-box model provides maximum flexibility for users, with formal security guarantees via static type checking. The black-box model simplifies execution for pre-vetted functions, with security enforced via Denning’s lattice rules. This dual model balances flexibility and security, while ensuring all program executions comply with our security goals.

### 3.5 IdP Root of Trust Reused from Assignment 1
- **Choice**: We reuse the IdP and OpenAuth protocol from Assignment 1 as the root of trust for identity and authorization.
- **Reasoning**: The OpenAuth protocol was formally verified with OFMC in Assignment 1 with no attacks found. Reusing this trusted infrastructure avoids introducing new authentication vulnerabilities and ensures consistency between the two assignments.

---

## 4 Server API Specification


This section defines the complete server API, the only interface for user-server interaction. All API calls require a valid IdP-signed OpenAuth authorization token (from Assignment 1) for identity verification, and all transmissions use a TLS-secured channel.

For every API call, the server performs two mandatory pre-checks first:
1.  Validate the token signature and freshness using the IdP’s public key;
2.  Verify the caller has permission to perform the operation (e.g., is the data owner, in the effective reader/writer set).

If either check fails, the server immediately returns `ERROR_UNAUTHORIZED` and aborts the operation.

### 4.1 Data Management Commands
This class handles data upload, label modification, query, and deletion.

#### Command 1: `upload_data`
**Function Signature**:
```python
upload_data(
    auth_token: SignedIdPToken,
    data_id: String,
    data: Binary,
    dlm_conf_label: DLMConfidentialityLabel,
    dlm_integ_label: DLMIntegrityLabel,
    lattice_class: (ConfidentialityClass, IntegrityClass)
) -> Response
```

**Parameter Constraints**:
- `Owners(dlm_conf_label)` must match the user identity authenticated by `auth_token` (only the owner can set the label for new data);
- `lattice_class` must be a valid class in the product lattice, and must be consistent with the DLM labels.

**Server Execution Logic (Pseudocode)**:
```python
def upload_data(auth_token, data_id, data, dlm_conf_label, dlm_integ_label, lattice_class):
    # Precondition checks
    caller_id = validate_idp_token(auth_token)
    if not caller_id:
        return ERROR_UNAUTHORIZED
    if caller_id not in Owners(dlm_conf_label):
        return ERROR_UNAUTHORIZED
    if not validate_label_consistency(dlm_conf_label, dlm_integ_label, lattice_class):
        return ERROR_INVALID_LABEL
    if data_id exists in caller_id's storage:
        return ERROR_DUPLICATE_DATA_ID
    
    # Store data and metadata
    secure_storage[caller_id][data_id] = {
        "data": data,
        "conf_label": dlm_conf_label,
        "integ_label": dlm_integ_label,
        "lattice_class": lattice_class
    }
    
    # Log to immutable audit log
    audit_log.log(caller_id, "upload_data", data_id, dlm_conf_label, dlm_integ_label)
    
    return SUCCESS_DATA_UPLOADED(data_id)
```

**Error Responses**:
- `ERROR_UNAUTHORIZED`: Token validation failed or caller is not the label owner;
- `ERROR_INVALID_LABEL`: Label or lattice class is invalid/inconsistent;
- `ERROR_DUPLICATE_DATA_ID`: data_id already exists for the owner.

---

### Command 2: modify_data_label
**Function Signature**:
```python
modify_data_label(
    auth_token: SignedIdPToken,
    data_id: String,
    new_dlm_conf_label: DLMConfidentialityLabel,
    new_dlm_integ_label: DLMIntegrityLabel,
    new_lattice_class: (ConfidentialityClass, IntegrityClass)
) -> Response
```

**Parameter Constraints**:
- The caller must be the owner of the data;
- `old_label ≤ new_label` (complies with the DLM partial order), unless the operation is an explicit declassification (governed by Section 6).

**Server Execution Logic**:
1. Perform precondition checks;
2. Verify the caller is the data owner;
3. Validate the new label and lattice class, and check compliance with the DLM partial order;
4. Update the data's bound label and lattice class;
5. Log the operation in the immutable audit log.

**Success Response**: `SUCCESS_LABEL_UPDATED(data_id)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Not the data owner or token invalid;
- `ERROR_INVALID_LABEL`: New label violates the lattice partial order;
- `ERROR_DATA_NOT_FOUND`: data_id does not exist.

---

### Command 3: read_data
**Function Signature**:
```python
read_data(
auth_token: SignedIdPToken,
data_id: String,
owner_id: AgentID
) -> Response
```

**Server Execution Logic**:
1. Perform precondition checks;
2. Retrieve the data's DLM label and verify the authenticated caller is in the EffectiveReaders set;
3. If authorized, return the data;
4. Log the read operation in the audit log.

**Success Response**: `SUCCESS_DATA_RETURNED(data_id, data)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Caller not in the effective reader set or token invalid;
- `ERROR_DATA_NOT_FOUND`: data_id does not exist.

---

### Command 4: delete_data
**Function Signature**:
```python
delete_data(
auth_token: SignedIdPToken,
data_id: String
) -> Response
```

**Server Execution Logic**:
1. Perform precondition checks;
2. Verify the caller is the data owner;
3. Permanently delete the data and its associated metadata;
4. Log the deletion in the audit log.

**Success Response**: `SUCCESS_DATA_DELETED(data_id)`

**Error Responses**:
- `ERROR_UNAUTHORIZED`: Not the data owner or token invalid;
- `ERROR_DATA_NOT_FOUND`: data_id does not exist.

## 4.2 Authorization & Sharing Commands
These commands enable the Data Owner to grant or revoke access to other users, aligned with the DLM label model.

### Command 5: grant_read_access
**Function Signature**:
```python
grant_read_access(
auth_token: SignedIdPToken,
data_id: String,
grantee_id: AgentID
) -> Response
```

**Server Execution Logic**:
1. Perform precondition checks;
2. Verify the caller is the data owner;
3. Add grantee_id to the owner's reader set in the data's DLM confidentiality label;
4. Update the data's label and log the operation.

**Success Response**: `SUCCESS_READ_ACCESS_GRANTED(data_id, grantee_id)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Not the data owner or token invalid;
- `ERROR_DATA_NOT_FOUND`: data_id does not exist.

---

### Command 6: revoke_read_access
**Function Signature**:
```python
revoke_read_access(
auth_token: SignedIdPToken,
data_id: String,
revokee_id: AgentID
) -> Response
```

**Server Execution Logic**:
1. Perform precondition checks;
2. Verify the caller is the data owner;
3. Remove revokee_id from the owner's reader set in the data's DLM confidentiality label;
4. Update the data's label and log the operation.

**Success Response**: `SUCCESS_READ_ACCESS_REVOKED(data_id, revokee_id)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Not the data owner or token invalid;
- `ERROR_DATA_NOT_FOUND`: data_id does not exist.

## 4.3 Program Management & Execution Commands
These commands govern the upload, static analysis, and secure execution of untrusted programs, aligned with the dual execution model and Volpano type system.

### Command 7: upload_program
**Function Signature**:
```python
upload_program(
auth_token: SignedIdPToken,
program_id: String,
source_code: String,
input_type_spec: List[(VariableName, SecurityType)],
output_type_spec: List[(VariableName, SecurityType)]
) -> Response
```

**Server Execution Logic**:
1. Perform precondition checks;
2. Store the program source code and type specifications bound to program_id and the owner's identity;
3. Trigger the static_analyze_program command automatically;
4. Log the upload operation.

**Success Response**: `SUCCESS_PROGRAM_UPLOADED(program_id)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Token invalid;
- `ERROR_DUPLICATE_PROGRAM_ID`: program_id already exists for the owner.

---

### Command 8: static_analyze_program
**Function Signature**:
```python
static_analyze_program(
auth_token: SignedIdPToken,
program_id: String
) -> Response
```

**Server Execution Logic (Pseudocode)**:
```python
def static_analyze_program(auth_token, program_id):
    # Precondition checks
    caller_id = validate_idp_token(auth_token)
    if not caller_id:
        return ERROR_UNAUTHORIZED
    program = get_program(caller_id, program_id)
    if not program:
        return ERROR_PROGRAM_NOT_FOUND
    
    # Build type environment from input/output type specs
    gamma = build_type_environment(program.input_type_spec, program.output_type_spec)
    
    # Run Volpano type checker on AST
    ast = parse_source_code(program.source_code)
    type_check_result, error_details = volpano_type_check(ast, gamma)
    
    # Update program status
    if type_check_result == PASS:
        program.status = "APPROVED_FOR_EXECUTION"
    else:
        program.status = "REJECTED"
    
    # Log analysis result
    audit_log.log(caller_id, "static_analyze_program", program_id, program.status, error_details)
    
    if type_check_result == PASS:
        return SUCCESS_ANALYSIS_COMPLETED(program_id, "APPROVED_FOR_EXECUTION")
    else:
        return ERROR_TYPE_CHECK_FAILED(error_details)
```

**Success Response**: `SUCCESS_ANALYSIS_COMPLETED(program_id, APPROVED_FOR_EXECUTION)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: Not the program owner or token invalid;
- `ERROR_PROGRAM_NOT_FOUND`: program_id does not exist;
- `ERROR_TYPE_CHECK_FAILED`: Program is not type-well-formed, with error details.

---

### Command 9: execute_program
**Function Signature**:
```python
execute_program(
auth_token: SignedIdPToken,
program_id: String,
input_data_ids: List[(VariableName, DataID, OwnerID)],
output_data_id: String,
output_dlm_conf_label: DLMConfidentialityLabel,
output_dlm_integ_label: DLMIntegrityLabel
) -> Response
``` 

**Parameter Constraints**:
- For white-box programs: program_id must be marked `APPROVED_FOR_EXECUTION`;
- The caller must be in the effective reader set of all input data, and the owner of the output data;
- The output label must comply with the lattice partial order for all input data.

**Server Execution Logic**:
1. Perform precondition checks;
2. Verify the caller has read access to all input data, and is the owner of the output data;
3. For white-box programs: Verify the input data's security types match the program's input type specification, and the output label matches the program's output type specification;
4. For black-box programs: Verify the output label's security class is the upper bound of all input data's security classes (per Denning's lattice rules);
5. Execute the program in an isolated sandbox, with access only to the specified input data;
6. Write the program output to output_data_id, bound to the validated output labels;
7. Log the execution, input/output data IDs, and execution status.

**Success Response**: `SUCCESS_PROGRAM_EXECUTED(program_id, output_data_id)`
**Error Responses**:
- `ERROR_UNAUTHORIZED`: No access to input data, or token invalid;
- `ERROR_PROGRAM_NOT_APPROVED`: White-box program not approved via static analysis;
- `ERROR_INVALID_OUTPUT_LABEL`: Output label violates lattice partial order;
- `ERROR_PROGRAM_EXECUTION_FAILED`: Runtime error during program execution.

## 4.4 Declassification Command
### Command 10: declassify_data
**Function Signature**:
```python
declassify_data(
auth_token: SignedIdPToken,
data_id: String,
declassified_conf_label: DLMConfidentialityLabel,
declassified_lattice_class: (ConfidentialityClass, IntegrityClass),
justification: String
) -> Response
```

This command is governed by the DLM declassification rules from Lecture 3, with full justification in Section 6.

# 5 Information Flow Security Proof for API Commands


This section provides a precise, per-command proof that no API operation can introduce illegal information flows, strictly based on the three required course papers and lecture materials. All proofs assume the mandatory precondition checks (token validation, identity authentication) have passed successfully.

---

## 5.1 Data Management Commands

### Proof for upload_data
**Security Claim**: Executing `upload_data` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. The caller is the sole owner of the new data, and defines the initial DLM labels and lattice class. The server validates that the labels and lattice class are valid and consistent with the product lattice rules (Denning & Denning, 1977).
2. The data is stored in an isolated partition bound exclusively to the owner's identity and the validated labels. No other principals have access to the data unless explicitly added to the effective reader set by the owner.
3. No cross-object information flow occurs during this operation: the data originates from the owner, and is written to an object with a label defined by the owner, complying with the lattice partial order.
4. No implicit flows are introduced, as there are no conditional operations that could leak sensitive information via control flow.

**Conclusion**: No illegal information flow is possible.

---

### Proof for modify_data_label
**Security Claim**: Executing `modify_data_label` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. Only the data owner can execute this command. The server validates that the new label complies with the DLM partial order `old_label ≤ new_label` (Myers & Liskov, 1997), meaning the new effective reader set is a subset of the old effective reader set (stricter confidentiality) and the new effective writer set is a subset of the old effective writer set (stricter integrity).
2. Modifying the label to a stricter class cannot introduce new access to the data, and thus cannot create an illegal flow of high-confidentiality data to lower-confidentiality principals.
3. No data is read or modified during this operation, eliminating both explicit and implicit flows between data objects.

**Conclusion**: No illegal information flow is possible.

---

### Proof for read_data
**Security Claim**: Executing `read_data` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. The server verifies that the caller is in the data's effective reader set before returning any data. Per the DLM model, the effective reader set is defined exclusively by the data owner.
2. The operation only transfers data from the server's storage to an authorized caller, which is a legal flow per the lattice rules: the data's label is unchanged, and the recipient is explicitly authorized to read the data.
3. No write operations are performed, eliminating the risk of data leakage to unauthorized objects. No implicit flows are introduced, as the operation has no conditional control flow that depends on sensitive data.

**Conclusion**: No illegal information flow is possible.

---

### Proof for delete_data
**Security Claim**: Executing `delete_data` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. Only the data owner can execute this command. The operation permanently deletes the data and its associated metadata, with no information transfer to any other principal or object.
2. No read or write operations are performed on other data objects, eliminating any possibility of cross-object information flow.
3. No implicit flows are introduced, as the operation's outcome does not depend on the content of the sensitive data.

**Conclusion**: No illegal information flow is possible.

---

## 5.2 Authorization & Sharing Commands

### Proof for grant_read_access
**Security Claim**: Executing `grant_read_access` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. Only the data owner can execute this command. The operation adds a grantee to the owner's reader set in the data's DLM confidentiality label, which is an explicit, owner-authorized relaxation of confidentiality constraints.
2. Per the DLM model (Myers & Liskov, 1997), the data owner is the sole authority to define the reader set, making this a legitimate, owner-initiated label modification.
3. The operation does not transfer data to the grantee; it only updates access control rules for future read operations, which are still validated by the `read_data` precondition checks.
4. No data is read or modified during this operation, eliminating both explicit and implicit flows between data objects.

**Conclusion**: No illegal information flow is possible.

---

### Proof for revoke_read_access
**Security Claim**: Executing `revoke_read_access` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. Only the data owner can execute this command. The operation removes a revokee from the owner's reader set in the data's DLM confidentiality label, which is a tightening of confidentiality constraints, reducing the set of principals authorized to access the data.
2. This operation cannot introduce new access to the data, and thus cannot create an illegal information flow. After revocation, the revokee can no longer pass the `read_data` precondition checks, eliminating future access.
3. No data is read or modified during this operation, eliminating both explicit and implicit flows.

**Conclusion**: No illegal information flow is possible.

---

## 5.3 Program Management & Execution Commands

### Proof for upload_program & static_analyze_program
**Security Claim**: Executing `upload_program` and `static_analyze_program` cannot introduce illegal explicit or implicit information flows.

**Proof**:
1. `upload_program` only stores the program source code and type specifications in the owner's isolated partition, with no access to any user data. No information flow occurs during this operation.
2. `static_analyze_program` runs the Volpano type checker on the program source code, with no access to user data and no code execution.
3. The type checker enforces all rules from Lecture 2, including explicit flow constraints (assignment, arithmetic operations) and implicit flow constraints (if/while control flow).
4. The core guarantee of Volpano's type system is non-interference: type-well-formed programs cannot leak high-security inputs via low-security outputs, eliminating all illegal explicit and implicit flows.
5. No user data is accessed or modified during these operations, eliminating any risk of information leakage or integrity contamination.

**Conclusion**: No illegal information flow is possible.

---

### Proof for execute_program
**Security Claim**: Executing `execute_program` cannot introduce illegal explicit or implicit information flows.

**Proof**:
We split the proof for the two execution models:

#### White-box Model Proof
1. Precondition checks verify the program is type-well-formed (approved via static analysis), and the caller has read access to all input data.
2. The server validates that the input data's security types match the program's input type specification, and the output label matches the program's output type specification.
3. Per the Non-Interference Theorem (Lecture 2), a type-well-formed program guarantees that changes to high-confidentiality inputs cannot be observed in low-confidentiality outputs, and no low-integrity input can contaminate high-integrity outputs. This covers all explicit and implicit flows.
4. The program is executed in an isolated sandbox, with access only to the specified input data. No other data is accessible to the program, eliminating cross-object information leakage.
5. The program output is written to an object with a pre-validated label that complies with the lattice partial order, ensuring all flows from input to output are legal per Denning & Denning (1977).

#### Black-box Model Proof
1. Precondition checks verify the caller has read access to all input data.
2. The server enforces that the output label's security class is the upper bound of all input data's security classes, per Denning's lattice rules. This ensures that the output's confidentiality is at least as strict as the most confidential input, and the output's integrity is at most as high as the least integral input.
3. Even if the black-box program contains malicious code, the output label guarantees that no high-confidentiality data can flow to a lower-confidentiality object, and no low-integrity data can contaminate a high-integrity object.
4. The program is executed in an isolated sandbox, with no access to data outside the specified inputs.

**Conclusion**: For both execution models, no illegal explicit or implicit information flow is possible.

# 6 Declassification Design & Compliance Justification

This section provides full justification and formal compliance proof for the `declassify_data` command, strictly aligned with the Decentralized Label Model (DLM) from Myers & Liskov (1997) and Lecture 3 course materials. All design and rules adhere to the assignment's mandatory requirements for secure, owner-controlled declassification.

---

## 6.1 Core Declassification Rules (Lecture 3)
Declassification is defined as the process of relaxing the confidentiality constraints of data (i.e., lowering its security class in the lattice, or expanding the authorized reader set in the DLM label). The `declassify_data` command **can only be executed if all of the following mandatory conditions are met**:
1.  **Sole Owner Authorization**: The caller must be the sole owner of the target data (verified via the IdP-signed authentication token). No other principal, including the server or IdP, can initiate or approve a declassification operation.
2.  **Acts For Check**: The declassification operation must be wrapped in an `if_acts_for(declassify_process, owner)` block, which verifies that the process executing the declassification has explicit authority to act on behalf of the data owner (per Lecture 3 DLM requirements).
3.  **Owner-Only Relaxation**: The declassification may only relax the caller-owner's own reader constraints. It cannot modify, remove, or relax the confidentiality constraints of any other co-owner of the data (per core DLM principles).
4.  **Explicit Written Justification**: The owner must provide a clear, written justification for the declassification (e.g., "anonymization of medical records for academic research"), which is permanently recorded in the immutable audit log.
5.  **Atomic Operation**: Declassification is executed as an atomic transaction: the data's label is updated in a single, non-interruptible step, with no intermediate states that could introduce illegal information flows.

---

## 6.2 Declassification Example (Hospital Scenario, Lecture 4)
Below is a concrete, compliant declassification implementation for the hospital use case defined in the assignment, which aligns with all rules outlined in Section 6.1:

```python
# Hospital H is the owner of patient medical records
# Original label: {H: {H, treating_doctors}}, lattice class: TopSecret
# Declassification goal: release anonymized statistical data to researchers

# Anonymization program (type-checked and approved)
def anonymize_patient_data(medical_records):
    count = 0
    i = 0
    while i < medical_records.length:
        if medical_records[i].diagnosis == "DIABETES":
            count = count + 1
        i = i + 1
    # Declassify only the aggregate count
    if_acts_for(anonymize_patient_data, H):
        declassified_count = declassify(count, {H: {H, researchers}})
    return declassified_count

# Server declassification execution
def declassify_data(auth_token, data_id, declassified_conf_label, declassified_lattice_class, justification):
    caller_id = validate_idp_token(auth_token)
    if caller_id not in Owners(original_conf_label):
        return ERROR_UNAUTHORIZED
    # Verify only the owner's constraints are relaxed
    if not validate_owner_only_relaxation(original_conf_label, declassified_conf_label, caller_id):
        return ERROR_INVALID_DECLASSIFICATION
    # Update label and log
    update_data_label(data_id, declassified_conf_label, declassified_lattice_class)
    audit_log.log(caller_id, "declassify_data", data_id, original_conf_label, declassified_conf_label, justification)
    return SUCCESS_DATA_DECLASSIFIED(data_id)
```


---

## 6.3 Compliance Justification
This section verifies that our declassification design fully complies with the required course materials, assignment rules, and core security principles.

### Alignment with Myers & Liskov (1997) DLM Core Principles
Our declassification model is 100% compliant with the foundational DLM framework from the required paper and Lecture 3:
- Only the data owner can initiate declassification, with no third-party authority to relax confidentiality constraints;
- Declassification can only relax the owner's own reader set constraints, with no ability to alter the policies of other co-owners;
- Declassification is an explicit, atomic operation with no implicit flows, eliminating the risk of unintended data leakage;
- The mandatory `acts_for` check ensures that only explicitly authorized processes can perform declassification on the owner's behalf, preventing unauthorized programmatic declassification.

### Security Guarantee
Declassification only expands the data's effective reader set to principals explicitly authorized by the data owner, with full, immutable audit logging of every operation. It cannot introduce unauthorized access to the data, as the owner is the sole authority to approve the release of the data. The design ensures that declassification is a deliberate, traceable action, rather than an accidental or malicious information flow.

### Use Case Compliance
This model fully supports the real-world use cases outlined in the assignment:
1.  **Personal Photo Hosting**: A user can declassify private photos to a lower security class, granting read access to friends and family;
2.  **Medical Data Management**: A hospital can deidentify patient records, declassify the resulting aggregate statistical data to a lower security class, and grant read access to academic researchers.

All use cases are fully compliant with our declassification rules: they are owner-initiated, have a clear written justification, are fully auditable, and only relax the owner's own confidentiality constraints.

---

## 6.4 Security Proof for declassify_data
**Security Claim**: Executing `declassify_data` in full compliance with our defined rules cannot introduce illegal explicit or implicit information flows.

**Proof**:
1.  Only the data owner can execute the command, and the mandatory `acts_for` check ensures that the declassification operation is explicitly authorized by the data owner.
2.  Declassification is an explicit, owner-initiated release of data, which is a legitimate operation per the DLM model (Myers & Liskov, 1997). It is not an illegal information flow, as it is explicitly authorized by the sole owner of the data.
3.  The server validates that only the owner's own reader constraints are relaxed during the operation, ensuring that the confidentiality rights of any other co-owners are not violated.
4.  All declassification operations are permanently recorded in the immutable audit log, with the owner's identity, original label, new label, and written justification, ensuring full accountability for the operation.
5.  The operation only modifies the data's security label, and does not transfer, modify, or expose the data content itself. All future access to the data is still governed by the `read_data` precondition checks, which validate that the caller is in the updated effective reader set of the data.

**Conclusion**: No illegal information flow is possible during a rule-compliant `declassify_data` operation.
