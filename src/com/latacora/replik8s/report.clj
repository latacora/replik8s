(ns com.latacora.replik8s.report
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [com.latacora.replik8s.query :as query]
   [com.latacora.replik8s.query-utils :refer [directory->db]]
   [dk.ative.docjure.spreadsheet :as spreadsheet]
   [taoensso.timbre :as timbre])
  (:import
   (java.time LocalDateTime)
   (java.time.format DateTimeFormatter)))

(def severities
  "Centralized map for severity levels to prevent typos."
  {:high          "High"
   :medium        "Medium"
   :low           "Low"
   :informational "Informational"})

(def findings-map
  "A map of findings. Each finding has a query function, description, headers, and severity."
  {"pods-host-network-true"
   {:query-fn    query/pods-host-network-true
    :title       "Pods with Host Network Enabled"
    :description "Pods are running with `hostNetwork` enabled, which allows them to directly access the node's network stack. This bypasses network policies and can lead to unauthorized network access."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "hostNetwork" "hostIPC" "hostPID"]
    :severity    (:medium severities)}

   "pods-host-ipc-true"
   {:query-fn    query/pods-host-ipc-true
    :title       "Pods with Host IPC Enabled"
    :description "Pods are running with `hostIPC` enabled, allowing them to access the host's IPC namespace. This can be exploited by a compromised container to interact with other processes on the host."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "hostNetwork" "hostIPC" "hostPID"]
    :severity    (:medium severities)}

   "pods-host-pid-true"
   {:query-fn    query/pods-host-pid-true
    :title       "Pods with Host PID Enabled"
    :description "Pods are running with `hostPID` enabled, allowing them to see all processes on the host node. A compromised container could use this to gather information about the host and escalate privileges."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "hostNetwork" "hostIPC" "hostPID"]
    :severity    (:medium severities)}

   "containers-with-sensitive-hostpath-mounts"
   {:query-fn    query/containers-with-sensitive-hostpath-mounts
    :title       "Containers with Sensitive HostPath Volume Mounts"
    :description "Containers are mounting sensitive directories from the underlying host, using `hostPath`. This can provide a container with excessive privileges and lead to container escape."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "volume-name" "host-path" "container" "mount-path"]
    :severity    (:medium severities)}

   "pods-with-hostpath-volume"
   {:query-fn    query/pods-with-hostpath-volume
    :title       "Pods with HostPath Volume Mounts"
    :description "Pods are mounting a volume from the underlying host node using `hostPath`. This can be dangerous and may allow for privilege escalation if the pod is compromised."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "volume-name" "host-path" "container" "mount-path"]
    :severity    (:informational severities)}

   "pods-vulnerable-IngressNightmare"
   {:query-fn    query/pods-vulnerable-IngressNightmare
    :title       "Pods Potentially Vulnerable to Ingress Nightmare Vulnerability (CVE-2025-1974) "
    :description "A critical vulnerability (CVE-2025-1974) was discovered in the Kubernetes Ingress-NGINX Controller that allows unauthenticated remote code execution on the ingress controller pod. This vulnerability affects Ingress-Nginx Controller version 1.11.x before 1.11.5, as well as versions below 1.11.0. It has been fixed in versions 1.12.1 and later, as well as 1.11.5 and later."
    :headers     ["timestamp" "host" "namespace" "pod" "label-name" "label-version"]
    :severity    (:high severities)}

   "nodes-vulnerable-runc-escape"
   {:query-fn    query/nodes-vulnerable-runc-escape
    :title       "Nodes Potentially Vulnerable to runC Container Escape Vulnerability (CVE-2024-21626)"
    :description "Nodes are running a version of `runC` that is affected by a container escape vulnerability (CVE-2024-21626). The range of affected versions are >= v1.0.0-rc93, <=1.1.11. For containerd the fixed versions are 1.6.28 and 1.7.13, the range of affected versions are 1.4.7 to 1.6.27 and 1.7.0 to 1.7.12. For Docker the fixed version is 25.0.2."
    :headers     ["timestamp" "host" "name" "creationTimestamp" "containerRuntimeVersion"]
    :severity    (:high severities)}

   "rbac-full-permissions"
   {:query-fn    query/rbac-full-permissions
    :title       "RBAC Subjects with Full Wildcard Permissions"
    :description "RBAC subjects have been granted full wildcard ('*') permissions on all resources. This violates the principle of least privilege and significantly increases the risk of a cluster-wide compromise."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name" "rules"]
    :severity    (:high severities)}

   "rbac-full-api-permissions"
   {:query-fn    query/rbac-full-api-permissions
    :title       "RBAC Subjects with Full API Permissions"
    :description "RBAC subjects have been granted full permissions on all resources within one or more API groups. This can provide excessive permissions and violates the principle of least privilege."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name" "rules"]
    :severity    (:medium severities)}

   "rbac-full-delete-permissions"
   {:query-fn    query/rbac-full-delete-permissions
    :title       "RBAC Subjects with Full Delete Permissions"
    :description "RBAC subjects have been granted delete permissions on all resources within one or more API groups. This could allow for accidental or malicious deletion of critical resources."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name" "rules"]
    :severity    (:medium severities)}

   "rbac-sensitive-permissions"
   {:query-fn    query/rbac-sensitive-permissions
    :title       "RBAC Subjects with Sensitive Permissions"
    :description "RBAC subjects have been granted sensitive permissions, such as creating pods or exec-ing into containers. These permissions should be granted with caution as they can be used for privilege escalation."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name" "rules"]
    :severity    (:medium severities)}

   "rbac-special-principals-with-permissions"
   {:query-fn    query/rbac-special-principals-with-permissions
    :title       "System Principals with Granted Permissions"
    :description "System principals have been granted permissions. Granting permissions to these groups is discouraged as it can grant permissions to anonymous or \"all authenticated\" users."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name"]
    :severity    (:medium severities)}

   "rbac-default-service-account-with-permissions"
   {:query-fn    query/rbac-default-service-account-permissions
    :title       "Default Service Accounts with Permissions"
    :description "Default service accounts have been granted permissions. It is recommended to use dedicated service accounts for applications to follow the principle of least privilege."
    :headers     ["timestamp" "host" "binding-kind" "binding-namespace" "binding-name" "role-kind" "role-name" "subject-kind" "subject-namespace" "subject-name"]
    :severity    (:low severities)}

   "pods-with-default-service-account"
   {:query-fn    query/pods-with-service-account-token-mounted-and-default-sa
    :title       "Pods with Service Account Tokens Mounted Using the Default Service Account"
    :description "Pods are using the default service account and have a service account token mounted. This is risky if the default service account has been granted any permissions, as it can lead to workloads being granted unexpected permissions."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "service-account-name" "pod-automountServiceAccountToken" "service-account-automountServiceAccountToken"]
    :severity    (:low severities)}

   "pods-with-pod-identity-token"
   {:query-fn    query/pods-with-pod-identity-token
    :title       "Pods with AWS IAM Role Tokens (Pod Identity)"
    :description "Pods are configured with AWS IAM role tokens via Pod Identity. This indicates they have direct permissions to cloud resources, which should be carefully audited."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod"]
    :severity    (:informational severities)}

   "pods-with-direct-env-vars"
   {:query-fn    query/pods-with-direct-env-vars
    :title       "Pods with Potentially Insecure Environment Variables"
    :description "Pods have environment variables set directly in their definition. This could potentially expose secrets, as environment variables are not encrypted and can be inspected by anyone with access to the pod definition."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "env-var-name" "env-var-value"]
    :severity    (:low severities)}

   "container-missing-security-context"
   {:query-fn    query/container-missing-security-context
    :title       "Containers with Missing Security Context"
    :description "Containers are running without a security context defined at the pod or container level. This can lead to containers running with default, and potentially insecure, settings."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "pod-securityContext" "container-securityContext"]
    :severity    (:medium severities)}

   "containers-readonly-root-filesystem-false"
   {:query-fn    query/containers-readonly-root-filesystem-false
    :title       "Containers with Writable Root Filesystem"
    :description "Containers are running with a writable root filesystem. This could allow an attacker to persist malicious binaries or modify the container's configuration."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "pod-readOnlyRootFilesystem" "container-readOnlyRootFilesystem"]
    :severity    (:medium severities)}

   "containers-allow-privilege-escalation-true"
   {:query-fn    query/containers-allow-privilege-escalation-true
    :title       "Containers that Allow Privilege Escalation"
    :description "Containers are configured to allow privilege escalation via the allowPrivilegeEscalation parameter. This configuration allows applications to escalate their privilege entitlements at runtime, potentially gaining permissions exceeding those intended."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "pod-allowPrivilegeEscalation" "container-allowPrivilegeEscalation"]
    :severity    (:medium severities)}

   "containers-privileged-true"
   {:query-fn    query/containers-privileged-true
    :title       "Privileged Containers"
    :description "Containers are running in privileged mode, which disables most security mechanisms. A privileged container has root access to the host and can be used for container escape."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "pod-privileged" "container-privileged"]
    :severity    (:high severities)}

   "containers-with-added-capabilities"
   {:query-fn    query/containers-with-added-capabilities
    :title       "Containers with Added Capabilities"
    :description "Containers have been granted Linux capabilities beyond the default set. These capabilities can be abused to escalate privileges or compromise the host."
    :headers     ["timestamp" "host" "namespace" "owner-kind" "owner-name" "pod" "container" "capability"]
    :severity    (:medium severities)}

   "namespaces-missing-default-deny-ingress"
   {:query-fn    query/namespaces-missing-default-deny-ingress
    :title       "Namespaces Missing Default Deny Ingress Policy"
    :description "Namespaces do not have a default deny ingress network policy. This means that all pods in the namespace will allow ingress traffic by default, which can increase the attack surface."
    :headers     ["timestamp" "host" "namespace"]
    :severity    (:medium severities)}

   "namespaces-missing-default-deny-egress"
   {:query-fn    query/namespaces-missing-default-deny-egress
    :title       "Namespaces Missing Default Deny Egress Policy"
    :description "Namespaces do not have a default deny egress network policy. This means that all pods in the namespace will allow egress traffic by default, which can increase the attack surface."
    :headers     ["timestamp" "host" "namespace"]
    :severity    (:medium severities)}

   "netpol-allow-all-ingress"
   {:query-fn    query/netpol-allow-all-ingress
    :title       "Network Policy Allows All Ingress"
    :description "A network policy is configured to allow all ingress traffic to all pods in the namespace. This is overly permissive and should be reviewed."
    :headers     ["timestamp" "host" "namespace" "policy"]
    :severity    (:low severities)}

   "netpol-allow-all-egress"
   {:query-fn    query/netpol-allow-all-egress
    :title       "Network Policy Allows All Egress"
    :description "A network policy is configured to allow all egress traffic from all pods in the namespace. This is overly permissive and should be reviewed."
    :headers     ["timestamp" "host" "namespace" "policy"]
    :severity    (:low severities)}})

(defn findings
  "Runs all queries and returns a map of findings."
  [db]
  (reduce-kv (fn [acc query-name {:keys [query-fn]}]
               (let [results (query-fn db)]
                 (if (seq results)
                   (assoc acc query-name (set results))
                   acc)))
             {}
             findings-map))

(defn- get-timestamp []
  (.format (LocalDateTime/now) (DateTimeFormatter/ofPattern "yyyy-MM-dd'_'HH:mm")))

(def ^:private severity-order {(:high severities) 0, (:medium severities) 1, (:low severities) 2, (:informational severities) 3})

(defn- result->row
  "Normalizes a single result item into a vector for spreadsheet rows.
  If the item is a map, it uses the headers to create an ordered vector.
  If it's already a collection, it's returned as is."
  [item headers]
  (if (map? item)
    (let [projection-fn (apply juxt (map keyword headers))]
      (projection-fn item))
    item))

(defn generate-report
  "Generates a report of all findings in the specified format.
  Accepts an optional output directory, defaulting to the current directory."
  ([format] (generate-report format "snapshots" "."))
  ([format snapshot-dir output-dir]
   (timbre/infof "Generating (%s) report from the %s directory, saving it to %s" (name format) snapshot-dir output-dir)
   (let [db        (directory->db snapshot-dir)
         results   (findings db)
         timestamp (get-timestamp)]
     (io/make-parents (str output-dir "/"))
     (case format
       :json
       (let [filename  (str "replik8s-report-" timestamp ".json")
             full-path (str output-dir "/" filename)
             json-data (reduce-kv (fn [m check-name check-results]
                                    (assoc m check-name {:title       (get-in findings-map [check-name :title])
                                                         :description (get-in findings-map [check-name :description])
                                                         :severity    (get-in findings-map [check-name :severity])
                                                         :items       check-results}))
                                  {}
                                  results)]
         (spit full-path (json/write-str json-data {:pretty true}))
         (timbre/infof "JSON report generated at %s" full-path))

       :xlsx
       (let [filename           (str "replik8s-report-" timestamp ".xlsx")
             full-path          (str output-dir "/" filename)
             sorted-check-names (sort-by #(get severity-order (get-in findings-map [% :severity])) (keys results))
             summary-sheet-name "Findings Summary"
             summary-header     ["Finding #" "Severity" "Title" "Description"]
             summary-rows       (map-indexed (fn [idx check-name]
                                               (let [{:keys [severity title description]} (get findings-map check-name)]
                                                 [(inc idx) severity title description]))
                                             sorted-check-names)
             summary-data       (cons summary-header summary-rows)
             workbook           (spreadsheet/create-workbook summary-sheet-name summary-data)
             bold-style         (spreadsheet/create-cell-style! workbook {:font {:bold true}})]

         ;; Style the summary sheet.
         (let [sheet (spreadsheet/select-sheet summary-sheet-name workbook)]
           (spreadsheet/set-row-style! (first (spreadsheet/row-seq sheet)) bold-style)
           (spreadsheet/auto-size-all-columns! sheet))

         ;; Create and style detail sheets for each finding.
         (doseq [[idx check-name] (map-indexed vector sorted-check-names)]
           (let [finding-num-str (str (inc idx))
                 {:keys [headers]} (get findings-map check-name)
                 check-results   (get results check-name)
                 rows            (map #(result->row % headers) check-results)
                 sheet-data      (cons headers rows)
                 sheet           (spreadsheet/add-sheet! workbook finding-num-str)]
             (spreadsheet/add-rows! sheet sheet-data)
             (spreadsheet/set-row-style! (first (spreadsheet/row-seq sheet)) bold-style)
             (spreadsheet/auto-size-all-columns! sheet)))

         (spreadsheet/save-workbook! full-path workbook)
         (timbre/infof "Spreadsheet report generated at %s" full-path)))

     (timbre/info "Report generation complete."))))

(comment
  (generate-report :json)

  (generate-report :xlsx))
