(ns com.latacora.replik8s.query
  (:require
   [clojure.string]
   [com.latacora.replik8s.query-rules :refer [rules]]
   [com.latacora.replik8s.query-utils :refer [directory->db]]
   [com.latacora.replik8s.utils]
   [datascript.core :as d]))

(defn pods-host-network-true
  "Query for pods with hostNetwork set to true"
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?name ?host-network ?host-ipc ?host-pid
         :keys timestamp host namespace owner-kind owner-name pod hostNetwork hostIPC hostPID
         :in $ %
         :where
         (pod ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec)
         (safe-get ?spec :hostNetwork ?host-network)
         (safe-get ?spec :hostIPC ?host-ipc)
         (safe-get ?spec :hostPID ?host-pid)
         [(true? ?host-network)]]
       db rules))

(defn pods-host-ipc-true
  "Query for pods with hostIPC set to true"
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?name ?host-network ?host-ipc ?host-pid
         :keys timestamp host namespace owner-kind owner-name pod hostNetwork hostIPC hostPID
         :in $ %
         :where
         (pod ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec)
         (safe-get ?spec :hostNetwork ?host-network)
         (safe-get ?spec :hostIPC ?host-ipc)
         (safe-get ?spec :hostPID ?host-pid)
         [(true? ?host-ipc)]]
       db rules))

(defn pods-host-pid-true
  "Query for pods with hostPID set to true"
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?name ?host-network ?host-ipc ?host-pid
         :keys timestamp host namespace owner-kind owner-name pod hostNetwork hostIPC hostPID
         :in $ %
         :where
         (pod ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec)
         (safe-get ?spec :hostNetwork ?host-network)
         (safe-get ?spec :hostIPC ?host-ipc)
         (safe-get ?spec :hostPID ?host-pid)
         [(true? ?host-pid)]]
       db rules))

(defn pods-vulnerable-IngressNightmare
  "Query for pods vulnerable to Ingress Nightmare"
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?name ?label-name ?label-version
         :keys timestamp host namespace pod label-name label-version
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         [?snapshot :resources ?r]
         [?r :api_v1_pods ?pods]
         [?pods :items ?i]
         [?i :metadata ?metadata]
         [?metadata :name ?name]
         [?metadata :namespace ?namespace]
         [?metadata :labels ?labels]
         [?labels :name "ingress-nginx"]
         [?labels :name ?label-name]
         [?labels :version ?label-version]
         ;; This vulnerability is fixed in Ingress NGINX Controller version 1.12.1 and 1.11.5.
         (or-join [?label-version]
                  [(= ?label-version "1.12.0")]
                  [(not (com.latacora.replik8s.utils/version-greater-or-equal? ?label-version "1.11.5"))])]
       db rules))

(defn nodes-vulnerable-runc-escape
  "Query for nodes vulnerable to CVE-2024-21626 runC container escape vulnerability"
  [db]
  (d/q '[:find ?timestamp ?host ?name ?creationTimestamp ?containerRuntimeVersion
         :keys timestamp host name creationTimestamp containerRuntimeVersion
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         [?snapshot :resources ?r]
         [?r :api_v1_nodes ?nodes]
         [?nodes :items ?i]
         [?i :metadata ?metadata]
         [?metadata :name ?name]
         [?metadata :creationTimestamp ?creationTimestamp]
         [?i :status ?status]
         [?status :nodeInfo ?nodeInfo]
         [?nodeInfo :containerRuntimeVersion ?containerRuntimeVersion]
         ;; For containerd, the range of affected versions are 1.4.7 to 1.6.27 and 1.7.0 to 1.7.12.
         [(clojure.string/starts-with? ?containerRuntimeVersion "containerd://")]
         [(clojure.string/replace ?containerRuntimeVersion #"containerd://" "") ?containerRuntimeVersion-number]
         (or-join [?containerRuntimeVersion-number]
                  (and
                   [(com.latacora.replik8s.utils/version-greater-or-equal? ?containerRuntimeVersion-number "1.4.7")]
                   (not [(com.latacora.replik8s.utils/version-greater-or-equal? ?containerRuntimeVersion-number "1.6.28")]))
                  (and
                   [(com.latacora.replik8s.utils/version-greater-or-equal? ?containerRuntimeVersion-number "1.7.0")]
                   (not [(com.latacora.replik8s.utils/version-greater-or-equal? ?containerRuntimeVersion-number "1.7.13")])))]
       db rules))

(defn rbac-full-permissions
  "Principals with full permissions"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name ?role-rule-string
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name rules
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
         [?role-rule :apiGroups "*"]
         [?role-rule :verbs "*"]
         [?role-rule :resources "*"]
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)]
       db rules))

(defn rbac-full-api-permissions
  "Principals with full permissions against an API"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name ?role-rule-string
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name rules
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
         [?role-rule :apiGroups ?api-groups]
         [(not= ?api-groups "*")]
         (or
          [?role-rule :verbs "*"]
          (and
           [?role-rule :verbs "list"]
           [?role-rule :verbs "get"]
           [?role-rule :verbs "create"]
           [?role-rule :verbs "delete"]
           [?role-rule :verbs "patch"]
           [?role-rule :verbs "update"]
           [?role-rule :verbs "watch"]
           [?role-rule :verbs "deletecollection"]))
         [?role-rule :resources "*"]
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)]
       db rules))

(defn rbac-full-delete-permissions
  "Principals with full delete permissions against an API"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name ?role-rule-string
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name rules
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
         [?role-rule :apiGroups ?api-groups]
         (or
          [?role-rule :verbs "delete"]
          [?role-rule :verbs "deletecollection"])
         [?role-rule :resources "*"]
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)]
       db rules))

(defn rbac-sensitive-permissions
  "Principals with sensitive permissions"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name ?role-rule-string
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name rules
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
         (sensitive-permissions ?role-rule ?issue)
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)]
       db rules))

(defn rbac-special-principals-with-permissions
  "Special principals with permissions"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)
         ;; flag system principals
         [(clojure.string/starts-with? ?subject-name "system:")]
         ;; exclude system bindings
         (not [(clojure.string/starts-with? ?binding-name "system:")])
         ;; exclude EKS system bindings
         (not [(clojure.string/starts-with? ?binding-name "eks:")])
         ;; exclude cluster-admin binding
         [(not= ?binding-name "cluster-admin")]]
       db rules))

(defn rbac-default-service-account-permissions
  "Default service accounts with permissions"
  [db]
  (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name
         :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)
         [(= ?subject-kind "ServiceAccount")]
         [(= ?subject-name "default")]]
       db rules))

(defn pods-with-direct-env-vars
  "Query for pods with environment variables set directly (not from a secret)."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?env-var-name ?env-var-value
         :keys timestamp host namespace owner-kind owner-name pod container env-var-name env-var-value
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         [?container :env ?env]
         [?env :name ?env-var-name]
         [?env :value ?env-var-value]]
       db rules))

(defn pods-with-pod-identity-token
  "Query for pods with a pod identity token mounted."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name
         :keys timestamp host namespace owner-kind owner-name pod
         :in $ %
         :where
         (pod ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec)
         [?spec :volumes ?volume]
         [?volume :name "eks-pod-identity-token"]]
       db rules))

(defn pods-with-service-account-token-mounted-and-default-sa
  "Query for pods using the default service account and where the token is mounted."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?service-account-name ?pod-automountServiceAccountToken ?service-account-automountServiceAccountToken
         :keys timestamp host namespace owner-kind owner-name pod service-account-name pod-automountServiceAccountToken service-account-automountServiceAccountToken
         :in $ %
         :where
         ;(container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (pod ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec)
         ;; ensure the pod is running with the default service account
         (or-join [?spec ?service-account-name]
                  (and
                   [?spec :serviceAccountName "default"]
                   [(ground "default") ?service-account-name])
                  (and
                   (not [?spec :serviceAccountName _])
                   [(ground "default (implicit)") ?service-account-name]))
         ;; get the pod configuration for the service account
         (or-join [?spec ?pod-automountServiceAccountToken]
                  ;; set
                  [?spec :automountServiceAccountToken ?pod-automountServiceAccountToken]
                  ;; not set
                  (and
                    ;(not [?spec :automountServiceAccountToken false])
                   (safe-get ?spec :automountServiceAccountToken ?automount)
                   [(= "Not set" ?automount)]
                   [(ground "Not set") ?pod-automountServiceAccountToken]))
         ;; Check the service account
         [?r :api_v1_serviceaccounts ?service-accounts]
         [?service-accounts :items ?sa]
         [?sa :metadata ?sa-metadata]
         [?sa-metadata :name "default"]
         [?sa-metadata :namespace ?namespace]
         ;; get the token configuration for the service account
         (or-join [?sa ?service-account-automountServiceAccountToken]
                  ;; set
                  [?sa :automountServiceAccountToken ?service-account-automountServiceAccountToken]
                  ;; not set
                  (and
                   (not [?sa :automountServiceAccountToken false])
                   [(ground "Not set") ?service-account-automountServiceAccountToken]))
         ;; evaluate the effective configuration
         (or-join [?pod-automountServiceAccountToken ?service-account-automountServiceAccountToken]
                  ;; The pod takes precedence
                  [(= true ?pod-automountServiceAccountToken)]
                  ;; If the pod specifies no value, it's mounted as long as the service account doesn't explicitly says otherwise
                  (and
                   [(= "Not set" ?pod-automountServiceAccountToken)]
                   [(not= false ?service-account-automountServiceAccountToken)]))]
       db rules))

(defn container-missing-security-context
  "Query for containers with a missing or empty security context."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?pod-security-context ?container-security-context
         :keys timestamp host namespace owner-kind owner-name pod container pod-securityContext container-securityContext
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (or-join [?spec ?pod-security-context]
                  ;; no security context
                  (and
                   (not [?spec :securityContext _])
                   [(ground "Not set") ?pod-security-context])
                  ;; empty security context
                  (and
                   [?spec :securityContext ?pod-sc]
                   (not [?pod-sc _ _])
                   [(ground "Not set") ?pod-security-context]))
         (or-join [?container ?container-security-context]
                  ;; no security context
                  (and
                   (not [?container :securityContext _])
                   [(ground "Not set") ?container-security-context])
                  ;; empty security context
                  (and [?container :securityContext ?container-sc]
                       (not [?container-sc _ _])
                       [(ground "Not set") ?container-security-context]))]
       db rules))

(defn containers-readonly-root-filesystem-false
  "Query for containers where readOnlyRootFilesystem is not enabled."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?pod-readonly-root-fs ?container-readonly-root-fs
         :keys timestamp host namespace owner-kind owner-name pod container pod-readOnlyRootFilesystem container-readOnlyRootFilesystem
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (pod-container-security-context-fields ?spec ?container ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user)
         ;; defaults to false
         (or-join [?pod-readonly-root-fs ?container-readonly-root-fs]
                  [(false? ?container-readonly-root-fs)]
                  (and [(= "Not set" ?container-readonly-root-fs)]
                       (not [(true? ?pod-readonly-root-fs)])))]
       db rules))

(defn containers-allow-privilege-escalation-true
  "Query for containers that allow privilege escalation."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?pod-allow-privesc ?container-allow-privesc
         :keys timestamp host namespace owner-kind owner-name pod container pod-allowPrivilegeEscalation container-allowPrivilegeEscalation
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (pod-container-security-context-fields ?spec ?container ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user)
         ;; defaults to true
         (or-join [?pod-allow-privesc ?container-allow-privesc]
                  [(true? ?container-allow-privesc)]
                  (and [(= "Not set" ?container-allow-privesc)]
                       (not [(false? ?pod-allow-privesc)])))]
       db rules))

(defn containers-privileged-true
  "Query for containers that allow privilege escalation."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?pod-privileged ?container-privileged
         :keys timestamp host namespace owner-kind owner-name pod container pod-privileged container-privileged
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (pod-container-security-context-fields ?spec ?container ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user)
         ;; defaults to false
         (or-join [?pod-privileged ?container-privileged]
                  [(true? ?container-privileged)]
                  [(true? ?pod-privileged)])]
       db rules))

(defn containers-with-added-capabilities
  "Query for containers that add capabilities."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?container-name ?capability
         :keys timestamp host namespace owner-kind owner-name pod container capability
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         (safe-get ?container :securityContext ?sc)
         (not [(= "Not set" ?sc)])
         (safe-get ?sc :capabilities ?caps)
         (not [(= "Not set" ?caps)])
         [?caps :add ?capability]]
       db rules))

(defn pods-with-hostpath-volume
  "Query for pods with a hostPath volume mount."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?volume-name ?host-path ?container-name ?mount-path
         :keys timestamp host namespace owner-kind owner-name pod volume-name host-path container mount-path
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         ;; pod volume
         [?spec :volumes ?volume]
         [?volume :name ?volume-name]
         [?volume :hostPath ?hp]
         [?hp :path ?host-path]
         ;; container
         [?container :volumeMounts ?volumeMount]
         [?volumeMount :name ?volume-name]
         [?volumeMount :mountPath ?mount-path]]
       db rules))

(defn containers-with-sensitive-hostpath-mounts
  "Query for containers mounting sensitive host paths."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?owner-kind ?owner-name ?pod-name ?volume-name ?host-path ?container-name ?mount-path
         :keys timestamp host namespace owner-kind owner-name pod volume-name host-path container mount-path
         :in $ %
         :where
         (container ?timestamp ?host ?namespace ?pod-name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
         ;; pod volume
         [?spec :volumes ?volume]
         [?volume :name ?volume-name]
         [?volume :hostPath ?hp]
         [?hp :path ?host-path]
         ;; container
         [?container :volumeMounts ?volumeMount]
         [?volumeMount :name ?volume-name]
         [?volumeMount :mountPath ?mount-path]
         (or [(= ?host-path "/")]
             [(= ?host-path "/etc")]
             [(= ?host-path "/proc")]
             [(= ?host-path "/var/run/docker.sock")]
             [(= ?host-path "/root")]
             [(clojure.string/starts-with? ?host-path "/var/log")])]
       db rules))

(defn namespaces-missing-default-deny-ingress
  "Query for namespaces missing a default deny ingress network policy."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace
         :keys timestamp host namespace
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         [?snapshot :resources ?r]
         [?r :api_v1_namespaces ?namespaces]
         [?namespaces :items ?ns-item]
         [?ns-item :metadata ?ns-meta]
         [?ns-meta :name ?namespace]
         ;; negate the clause
         (not
          (network-policy ?timestamp ?host ?namespace ?name ?spec)
          [?sped :podSelector ?ps]
           ;; Network policies are additive, so as long as there's a policy that targets all pods, then traffic
           ;; won't be allowed by default.
          (not [?ps _ _])
           ;; Set the direction
          (safe-get ?spec :policyTypes ?type)
          [(= ?type "Ingress")]
           ;; This return network policies that either don't allow any traffic, or don't allow all traffic (i.e.
           ;; policies that specify traffic that should be allowed).
           ;; has an ingress rule and it's empty
          (safe-get ?spec :ingress ?ingress)
          [(= ?ingress "Not set")]
          (not [?ingress _ _]))]
       db rules))

(defn namespaces-missing-default-deny-egress
  "Query for namespaces missing a default deny egress network policy."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace
         :keys timestamp host namespace
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         [?snapshot :resources ?r]
         [?r :api_v1_namespaces ?namespaces]
         [?namespaces :items ?ns-item]
         [?ns-item :metadata ?ns-meta]
         [?ns-meta :name ?namespace]
         ;; negate the clause
         (not
          (network-policy ?timestamp ?host ?namespace ?name ?spec)
          [?sped :podSelector ?ps]
           ;; Network policies are additive, so as long as there's a policy that targets all pods, then traffic
           ;; won't be allowed by default.
          (not [?ps _ _])
           ;; Set the direction
          (safe-get ?spec :policyTypes ?type)
          [(= ?type "Egress")]
           ;; This return network policies that either don't allow any traffic, or don't allow all traffic (i.e.
           ;; policies that specify traffic that should be allowed).
           ;; has an egress rule and it's empty
          (safe-get ?spec :egress ?egress)
          [(= ?egress "Not set")]
          (not [?egress _ _]))]
       db rules))

(defn netpol-allow-all-ingress
  "Query for network policies that allow all ingress traffic."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?name
         :keys timestamp host namespace policy
         :in $ %
         :where
         (network-policy ?timestamp ?host ?namespace ?name ?spec)
         (safe-get ?spec :podSelector ?ps)
         ;; desired policy type
         (safe-get ?spec :policyTypes ?type)
         [(= ?type "Ingress")]
         ;; has an ingress rule and it's empty
         (safe-get ?spec :ingress ?ingress)
         [(not= ?ingress "Not set")]
         (not [?ingress _ _])
         ;; empty podSelector
         (or-join [?ps]
                  (not [?ps _ _])
                  [(= ?ps nil)])]
       db rules))

(defn netpol-allow-all-egress
  "Query for network policies that allow all egress traffic."
  [db]
  (d/q '[:find ?timestamp ?host ?namespace ?name
         :keys timestamp host namespace policy
         :in $ %
         :where
         (network-policy ?timestamp ?host ?namespace ?name ?spec)
         (safe-get ?spec :podSelector ?ps)
         ;; desired policy type
         (safe-get ?spec :policyTypes ?type)
         [(= ?type "Egress")]
         ;; has an egress rule and it's empty
         (safe-get ?spec :egress ?egress)
         [(not= ?egress "Not set")]
         (not [?egress _ _])
         ;; empty podSelector
         (or-join [?ps]
                  (not [?ps _ _])
                  [(= ?ps nil)])]
       db rules))

(comment

  (def db (directory->db))

  (d/q '[:find ?timestamp ?host ?namespace ?name
         :keys timestamp host namespace pod
         :in $ %
         :where
         [?snapshot :metadata ?snapshot-metadata]
         [?snapshot-metadata :host ?host]
         [?snapshot-metadata :timestamp ?timestamp-int]
         [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
         [?snapshot :resources ?r]
         [?r :api_v1_pods ?pods]
         [?pods :items ?i]
         [?i :metadata ?metadata]
         [?metadata :name ?name]
         [?metadata :namespace ?namespace]
         [?i :spec ?spec]]
       db rules))
