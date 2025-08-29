(ns com.latacora.replik8s.query-rules)

(def rules '[[(safe-get ?map ?key-value ?value)
              [(ground ?key-value) ?key]
              (or-join [?map ?key ?value]
                       ;; exists
                       [?map ?key ?value]
                       ;; does not exist, return default
                       (and
                        (not [?map ?key _])
                        [(ground "Not set") ?value]))]
             ;; workloads
             [(pod ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec)
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
              (safe-get ?metadata :ownerReferences ?owner-references)
              (safe-get ?owner-references :kind ?owner-kind)
              (safe-get ?owner-references :name ?owner-name)
              [?i :spec ?spec]]
             [(container ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec ?container ?container-name ?container-image)
              (pod ?timestamp ?host ?namespace ?name ?owner-kind ?owner-name ?spec)
              [?spec :containers ?container]
              [?container :name ?container-name]
              [?container :image ?container-image]]
             [(pod-container-security-context-fields ?spec ?container ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user)
              ;; pod security context configuration
              (or-join [?spec ?pod-privileged ?pod-allow-privesc ?pod-readonly-root-fs ?pod-run-as-non-root ?pod-run-as-user]
                       (and
                        (safe-get ?spec :securityContext ?pod-sc)
                        [(not= ?pod-sc "Not set")]
                        (safe-get ?pod-sc :privileged ?pod-privileged)
                        (safe-get ?pod-sc :allowPrivilegeEscalation ?pod-allow-privesc)
                        (safe-get ?pod-sc :readOnlyRootFilesystem ?pod-readonly-root-fs)
                        (safe-get ?pod-sc :runAsNonRoot ?pod-run-as-non-root)
                        (safe-get ?pod-sc :runAsUser ?pod-run-as-user))
                       (and
                        (safe-get ?spec :securityContext ?pod-sc)
                        [(= ?pod-sc "Not set")]
                        [(ground "Not set") ?pod-privileged]
                        [(ground "Not set") ?pod-allow-privesc]
                        [(ground "Not set") ?pod-readonly-root-fs]
                        [(ground "Not set") ?pod-run-as-non-root]
                        [(ground "Not set") ?pod-run-as-user]))
              ;; container security context configuration
              (or-join [?container ?container-privileged ?container-allow-privesc ?container-readonly-root-fs ?container-run-as-non-root ?container-run-as-user]
                       (and
                        (safe-get ?container :securityContext ?container-sc)
                        [(not= ?container-sc "Not set")]
                        (safe-get ?container-sc :privileged ?container-privileged)
                        (safe-get ?container-sc :allowPrivilegeEscalation ?container-allow-privesc)
                        (safe-get ?container-sc :readOnlyRootFilesystem ?container-readonly-root-fs)
                        (safe-get ?container-sc :runAsNonRoot ?container-run-as-non-root)
                        (safe-get ?container-sc :runAsUser ?container-run-as-user))
                       (and
                        (safe-get ?container :securityContext ?container-sc)
                        [(= ?container-sc "Not set")]
                        [(ground "Not set") ?container-privileged]
                        [(ground "Not set") ?container-allow-privesc]
                        [(ground "Not set") ?container-readonly-root-fs]
                        [(ground "Not set") ?container-run-as-non-root]
                        [(ground "Not set") ?container-run-as-user]))]
             [(roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
              [?snapshot :metadata ?snapshot-metadata]
              [?snapshot-metadata :host ?host]
              [?snapshot-metadata :timestamp ?timestamp-int]
              [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
              [?snapshot :resources ?r]
              [(ground "ClusterRole") ?role-kind]
              [?r :apis_rbac_authorization_k8s_io_v1_clusterroles ?roles]
              [?roles :items ?i]
              [?i :metadata ?role-metadata]
              [?role-metadata :name ?role-name]
              [(ground "None") ?role-namespace]
              [?i :rules ?role-rule]
              [?i :rules.string ?role-rule-string]]
             [(roles ?timestamp ?host ?role-kind ?role-name ?role-namespace ?role-rule ?role-rule-string)
              [?snapshot :metadata ?snapshot-metadata]
              [?snapshot-metadata :host ?host]
              [?snapshot-metadata :timestamp ?timestamp-int]
              [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
              [?snapshot :resources ?r]
              [(ground "Role") ?role-kind]
              [?r :apis_rbac_authorization_k8s_io_v1_roles ?roles]
              [?roles :items ?i]
              [?i :metadata ?role-metadata]
              [?role-metadata :name ?role-name]
              [?role-metadata :namespace ?role-namespace]
              [?i :rules ?role-rule]
              [?i :rules.string ?role-rule-string]]
             ;; network policies
             [(network-policy ?timestamp ?host ?namespace ?name ?spec)
              [?snapshot :metadata ?snapshot-metadata]
              [?snapshot-metadata :host ?host]
              [?snapshot-metadata :timestamp ?timestamp-int]
              [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
              [?snapshot :resources ?r]
              [?r :apis_networking_k8s_io_v1_networkpolicies ?policies]
              [?policies :items ?item]
              [?item :metadata ?meta]
              [?meta :name ?name]
              [?meta :namespace ?namespace]
              [?item :spec ?spec]]
             ;; RBAC
             [(bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)
              [?snapshot :metadata ?snapshot-metadata]
              [?snapshot-metadata :host ?host]
              [?snapshot-metadata :timestamp ?timestamp-int]
              [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
              [?snapshot :resources ?r]
              [(ground "ClusterRoleBinding") ?binding-kind]
              [?r :apis_rbac_authorization_k8s_io_v1_clusterrolebindings ?bindings]
              [?bindings :items ?i]
              [?i :metadata ?binding-metadata]
              [?binding-metadata :name ?binding-name]
              [(ground "None") ?binding-namespace]
              [?i :roleRef ?role-ref]
              [?role-ref :kind ?role-kind]
              [?role-ref :name ?role-name]
              [?i :subjects ?binding-subjects]
              [?binding-subjects :kind ?subject-kind]
              [?binding-subjects :name ?subject-name]
              (or-join [?subject-kind ?binding-subjects ?subject-namespace]
                       (and
                        [(not= ?subject-kind "ServiceAccount")]
                        [(ground "None") ?subject-namespace])
                       (and
                        [(= ?subject-kind "ServiceAccount")]
                        [?binding-subjects :namespace ?subject-namespace]))]
             [(bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)
              [?snapshot :metadata ?snapshot-metadata]
              [?snapshot-metadata :host ?host]
              [?snapshot-metadata :timestamp ?timestamp-int]
              [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
              [?snapshot :resources ?r]
              [(ground "RoleBinding") ?binding-kind]
              [?r :apis_rbac_authorization_k8s_io_v1_rolebindings ?bindings]
              [?bindings :items ?i]
              [?i :metadata ?binding-metadata]
              [?binding-metadata :name ?binding-name]
              [?binding-metadata :namespace ?binding-namespace]
              [?i :roleRef ?role-ref]
              [?role-ref :kind ?role-kind]
              [?role-ref :name ?role-name]
              [?i :subjects ?binding-subjects]
              [?binding-subjects :kind ?subject-kind]
              [?binding-subjects :name ?subject-name]
              (or-join [?subject-kind ?binding-subjects ?subject-namespace]
                       (and
                        [(not= ?subject-kind "ServiceAccount")]
                        [(ground "None") ?subject-namespace])
                       (and
                        [(= ?subject-kind "ServiceAccount")]
                        [?binding-subjects :namespace ?subject-namespace]))]
             [(sensitive-permissions ?role-rule ?issue)
              (or-join [?role-rule ?issue]
                       ;; Workload creation or editing
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "core"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "deployments"]
                         [?role-rule :resources "replicationcontrollers"]
                         [?role-rule :resources "daemonsets"]
                         [?role-rule :resources "statefulsets"]
                         [?role-rule :resources "replicasets"]
                         [?role-rule :resources "pods"]
                         [?role-rule :resources "jobs"]
                         [?role-rule :resources "cronjobs"])
                        [(ground "Workload creation or editing") ?issue])
                       ;; Code execution in pods
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups ""])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "pods/exec"])
                        [(ground "Code execution in pods") ?issue])
                       ;; Access to secrets
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups ""])
                        (or
                         [?role-rule :verbs "get"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "secrets"])
                        [(ground "Access to secrets") ?issue])
                       ;; Privilege escalation via bind or escalate
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "rbac.authorization.k8s.io"])
                        (or
                         [?role-rule :verbs "bind"]
                         [?role-rule :verbs "escalate"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "clusterroles"]
                         [?role-rule :resources "roles"])
                        [(ground "Privilege escalation via bind or escalate") ?issue])
                       ;; Privilege escalation via impersonate
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "core"])
                        (or
                         [?role-rule :verbs "impersonate"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "users"]
                         [?role-rule :resources "groups"]
                         [?role-rule :resources "serviceaccounts"])
                        [(ground "Privilege escalation via impersonate") ?issue])
                       ;; Privilege escalation via role manipulation
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "rbac.authorization.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "clusterroles"]
                         [?role-rule :resources "roles"])
                        [(ground "Privilege escalation via role manipulation") ?issue])
                       ;; Privilege escalation via binding manipulation
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "rbac.authorization.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "rolebindings"]
                         [?role-rule :resources "clusterrolebindings"])
                        [(ground "Privilege escalation via binding manipulation") ?issue])
                       ;; Manipulate shared storage and data resources
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "core"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "persistentvolumeclaims"]
                         [?role-rule :resources "persistentvolumes"])
                        [(ground "Manipulate shared storage and data resources") ?issue])
                       ;; Manipulate shared storage and data resources
                       (and
                        (or
                         [?role-rule :apiGroups "storage.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "*"])
                        [(ground "Manipulate shared storage and data resources") ?issue])
                       ;; Manipulate shared networking resources
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "networking.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "networkpolicies"]
                         [?role-rule :resources "ingresses"]
                         [?role-rule :resources "ingressclasses"])
                        [(ground "Manipulate shared networking resources") ?issue])
                       ;; Manipulate shared networking resources
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "core"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "services"]
                         [?role-rule :resources "endpoints"])
                        [(ground "Manipulate shared networking resources") ?issue])
                       ;; Manipulate shared networking resources
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "discovery.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "endpointslices"])
                        [(ground "Manipulate shared networking resources") ?issue])
                       ;; Manipulate Gateway Api resources
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "gateway.networking.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "gatewayclasses"]
                         [?role-rule :resources "gateways"]
                         [?role-rule :resources "httproutes"]
                         [?role-rule :resources "tcproutes"]
                         [?role-rule :resources "tlsroutes"]
                         [?role-rule :resources "udproutes"])
                        [(ground "Manipulate Gateway Api resources") ?issue])
                       ;; Manipulate Admission Controllers
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "admissionregistration.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "mutatingwebhookconfigurations"]
                         [?role-rule :resources "validatingwebhookconfigurations"])
                        [(ground "Manipulate Admission Controllers") ?issue])
                       ;; Manipulate Cluster Extensions (CRDs)
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "apiextensions.k8s.io"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "customresourcedefinitions"])
                        [(ground "Manipulate Cluster Extensions (CRDs)") ?issue])
                       ;; Manipulate Open Policy Agent (OPA)
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "templates.gatekeeper.sh"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "constrainttemplates"])
                        [(ground "Manipulate Open Policy Agent (OPA)") ?issue])
                       ;; Manipulate Open Policy Agent (OPA)
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "mutations.gatekeeper.sh"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "assign"]
                         [?role-rule :resources "assignmetadata"])
                        [(ground "Manipulate Open Policy Agent (OPA)") ?issue])
                       ;; Manipulate Open Policy Agent (OPA)
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups "config.gatekeeper.sh"])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "delete"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "configs"])
                        [(ground "Manipulate Open Policy Agent (OPA)") ?issue])
                       ;; Create node proxies, which provides direct access to Kubelet APIs and can be used for privileges escalation
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups ""])
                        (or
                         [?role-rule :verbs "create"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "nodes/proxy"])
                        [(ground "Create node proxies, which provides direct access to Kubelet APIs and can be used for privileges escalation") ?issue])
                       ;; Create ephemeral containers in running pods
                       (and
                        (or
                         [?role-rule :apiGroups "*"]
                         [?role-rule :apiGroups ""])
                        (or
                         [?role-rule :verbs "patch"]
                         [?role-rule :verbs "update"]
                         [?role-rule :verbs "*"])
                        (or
                         [?role-rule :resources "pods/ephemeralcontainers"])
                        [(ground "create ephemeral containers in running pods") ?issue]))]])
