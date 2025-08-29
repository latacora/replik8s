(ns com.latacora.replik8s.visualize
  {:nextjournal.clerk/visibility {:code :hide :result :hide}}
  (:require
   [clojure.string]
   [com.latacora.replik8s.query-rules :refer [rules]]
   [com.latacora.replik8s.query-utils :refer [directory->db]]
   [com.latacora.replik8s.report :as report]
   [com.latacora.replik8s.utils :as utils]
   [datascript.core :as d]
   [nextjournal.clerk :as clerk]))

^{::clerk/visibility {:result :show}}
(clerk/md "# Snapshots")

(defonce db (directory->db))

(def clusters (d/q '[:find ?host ?timestamp
                     :in $
                     :where
                     [?snapshot :metadata ?snapshot-metadata]
                     [?snapshot-metadata :host ?host]
                     [?snapshot-metadata :timestamp ?timestamp-int]
                     [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]]
                   db))

^{::clerk/visibility {:result :show}}
(clerk/table (clerk/use-headers
              (concat [["Cluster" "Date"]] (sort-by (juxt first second) clusters))))

^{::clerk/visibility {:result :show}}
(clerk/md "# Findings")

(defonce findings-report (report/findings db))

(defn flatten-findings [report-map]
  (mapcat (fn [[finding-type instances]]
            (map (fn [instance-data] (assoc instance-data :finding-type finding-type
                                            :timestamp-epoch (utils/date-str->epoch (:timestamp instance-data)))) ; Add the finding type key
                 instances))
          report-map))

(def findings-data-flat (flatten-findings findings-report))

(def findings-vl-spec
  {:description "Daily count of findings per type"
   :data        {:values findings-data-flat}
   :width       400
   :params      [{:name   "finding_filter"
                  :select {:type "point" :fields ["finding-type"]}
                  :bind   {:input   "select"
                           :options (->> findings-data-flat (map :finding-type) distinct sort (cons nil))
                           :labels  (->> findings-data-flat (map :finding-type) distinct sort (cons "All"))
                           :name    "Finding: "}}]
   :transform   [{:filter {:param "finding_filter"}}
                 {:timeUnit "yearmonthdate"
                  :field    "timestamp-epoch"
                  :as       "binned_date"}
                 {:aggregate [{:op "count" :as "finding_count"}]
                  :groupby   ["binned_date", "finding-type"]}]
   :mark        {:type "line", :point true, :tooltip true}
   :encoding    {:x       {:field "binned_date"
                           :type  "temporal"
                           :title "Date"
                           :axis  {:format "%Y-%m-%d"}}
                 :y       {:field "finding_count"
                           :type  "quantitative"
                           :title "Findings Count"}
                 :color   {:field "finding-type"
                           :type  "nominal"
                           :title "Finding Type"}
                 :tooltip [{:field "finding-type" :title "Finding"}
                           {:field  "binned_date"
                            :type   "temporal"
                            :title  "Date"
                            :format "%Y-%m-%d"}
                           {:field "finding_count"
                            :type  "quantitative"
                            :title "Count on Date"}]}})

^{::clerk/visibility {:result :show}}
(clerk/vl findings-vl-spec)

^{::clerk/visibility {:result :show}}
(clerk/md "# Pods")

(def cluster (-> clusters first first))

^{::clerk/visibility {:result :show}}
(clerk/md (format "Pods for cluster %s." cluster))

^::clerk/no-cache
(def cluster-pods (d/q '[:find ?timestamp ?host ?namespace ?name
                         :keys timestamp host namespace pod
                         :in $ ?host
                         :where
                         [?snapshot :metadata ?snapshot-metadata]
                         [?snapshot-metadata :host ?host]
                         [?snapshot-metadata :timestamp ?timestamp]
                         [?snapshot :resources ?r]
                         [?r :api_v1_pods ?pods]
                         [?pods :items ?i]
                         [?i :metadata ?metadata]
                         [?metadata :name ?name]
                         [?metadata :namespace ?namespace]
                         [?i :spec ?spec]]
                       db cluster))

(def vl-spec
  {:data     {:values cluster-pods}
   :width    400
   :params   [{:name   "namespace_filter"
               :select {:type "point" :fields ["namespace"]}
               :bind   {:input   "select"
                        :options (->> cluster-pods (map :namespace) distinct (cons nil))
                        :labels  (->> cluster-pods (map :namespace) distinct (cons "All"))
                        :name    "Namespace: "}}]
   :mark     :circle
   :encoding {:x       {:field "timestamp"
                        :type "temporal"
                        :title "Date"
                        :axis {:format "%Y-%m-%d"}}
              :y       {:field "pod"
                        :type "nominal"
                        :title "Pod"}
              :color   {:field "namespace"
                        :type "nominal"
                        :title "Namespace"}
              :opacity {:condition {:selection "namespace_filter" :value 1}
                        :value     0.2}
              :tooltip [{:field "pod"
                         :title "Pod"}
                        {:field "namespace"
                         :title "Namespace"}
                        {:field "timestamp"
                         :type "temporal"
                         :title "Date"}]}})

^{::clerk/visibility {:result :show}}
(clerk/vl vl-spec)

^{::clerk/visibility {:result :show}}
(clerk/md "# RBAC Bindings")

^::clerk/no-cache
(def bindings (d/q '[:find ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name
                     :keys timestamp host binding-kind binding-namespace binding-name role-kind role-name subject-kind subject-namespace subject-name
                     :in $ %
                     :where
                     [?snapshot :metadata ?snapshot-metadata]
                     [?snapshot-metadata :host ?host]
                     [?snapshot-metadata :timestamp ?timestamp-int]
                     [(com.latacora.replik8s.utils/datetime->date-str ?timestamp-int) ?timestamp]
                     (bindings ?timestamp ?host ?binding-kind ?binding-namespace ?binding-name ?role-kind ?role-name ?subject-kind ?subject-namespace ?subject-name)]
                   db rules))

(def vega-lite-spec
  {:$schema     "https://vega.github.io/schema/vega-lite/v5.json"
   :description "Role to Subject Relationships (Filterable by Namespace)"
   :data        {:values bindings}
   :params      [{:name   "role_namespace_filter"
                  :select {:type "point" :fields ["binding-namespace"]}
                  :bind   {:input   "select"
                           :options (->> bindings
                                         (map :binding-namespace)
                                         distinct
                                         sort
                                         (cons nil))
                           :labels  (->> bindings
                                         (map :binding-namespace)
                                         distinct
                                         sort
                                         (cons "All"))
                           :name    "Namespace: "}}]
   :mark        {:type "point" :filled true :size 80}
   :encoding    {:x       {:field "role-name",
                           :type  "nominal",
                           :title "Role"
                           :axis  {:labelAngle -45}}
                 :y       {:field "subject-name",
                           :title "Subject",
                           :type  "nominal"}
                 :color   {:field "role-kind",
                           :type  "nominal"}
                 :shape   {:field "subject-kind",
                           :type  "nominal"}
                 :opacity {:condition {:param "role_namespace_filter"
                                       :value 1}
                           :value     0.1}
                 :tooltip [{:field "role-name" :title "Role"}
                           {:field "role-kind" :title "Role Kind"}
                           {:field "binding-namespace" :title "Binding Namespace"} ; Display the namespace on hover
                           {:field "subject-name" :title "Subject"}
                           {:field "subject-kind" :title "Subject Kind"}]}})

^{::clerk/visibility {:result :show}}
^{:nextjournal.clerk/width :full}
(clerk/vl vega-lite-spec)

(comment
  (clerk/serve! {:browse? true})
  (clerk/serve! {:watch-paths ["src"]})
  (clerk/show! "src/com/latacora/replik8s/visualize.clj"))
