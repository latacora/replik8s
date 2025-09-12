(ns com.latacora.replik8s.core
  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.tools.cli :refer [parse-opts]]
            [com.latacora.replik8s.collect :as collect]
            [com.latacora.replik8s.report :as report]
            [com.latacora.replik8s.serve :as serve]
            [nextjournal.clerk :as clerk])
  (:import (java.time LocalDateTime)
           (java.time.format DateTimeFormatter)))

(def collect-cli-options
  [["-d" "--snapshot-dir SNAPSHOPT_DIR" "Directory of the snapshots to load"
    :default "snapshots"]
   ["-k" "--kubeconfig KUBECONFIG" "Optional path to the kubeconfig file"
    :default (str (io/file (System/getProperty "user.home") ".kube/config"))]])

(def serve-cli-options
  [["-d" "--snapshot-dir SNAPSHOPT_DIR" "Directory of the snapshots to load"
    :default "snapshots"]])

(def report-cli-options
  [["-d" "--snapshot-dir SNAPSHOPT_DIR" "Directory of the snapshots to load"
    :default "snapshots"]
   ["-f" "--format FORMAT" "Report format: json or xlsx"
    :parse-fn keyword
    :default "xlsx"]
   ["-o" "--output-dir OUTPUT_DIR" "Directory to save the report"
    :default "."]])

(defn collect
  [options]
  (collect/generate-snapshot (:kubeconfig options)
                             (format "%s/replik8s-snapshot-%s.json"
                                     (:snapshot-dir options)
                                     (.format (LocalDateTime/now) (DateTimeFormatter/ofPattern "yyyy-MM-dd_HH:mm")))))

(defn serve
  [options]
  (serve/start-server (:snapshot-dir options)))

(defn report
  [options]
  (report/generate-report (:format options)
                          (:snapshot-dir options)
                          (:output-dir options)))

(defn visualize
  [options]
  (clerk/show! 'com.latacora.replik8s.visualize)
  (clerk/serve! {:browse? true}))

(def commands
  {"collect"   {:fn      collect
                :desc    "Generate a snapshot."
                :options collect-cli-options}
   "serve"     {:fn      serve
                :desc    "Start the server."
                :options serve-cli-options}
   "report"    {:fn      report
                :desc    "Generate findings."
                :options report-cli-options}
   "visualize" {:fn      visualize
                :desc    "Visualize snapshot."
                :options []}})

(defn usage []
  (println "Usage: replik8s <command> [options]")
  (println)
  (println "Commands:")
  (doseq [[cmd {:keys [desc]}] (sort-by key commands)]
    (println (format "  %-10s %s" cmd desc)))
  (println)
  (println "Run 'replik8s <command> --help' for more information on a command."))

(defn dispatch [args]
  (let [[cmd & cmd-args] args
        command (get commands cmd)]
    (if command
      (let [{:keys [fn desc options]} command
            cli-options (conj options ["-h" "--help" "Show help"])
            parsed      (parse-opts cmd-args cli-options)
            show-help?  (get-in parsed [:options :help])
            errors      (:errors parsed)]
        (if (or show-help? errors)
          (do
            (when desc (println desc))
            (println)
            (println (format "Usage: replik8s %s [options]" cmd))
            (println)
            (println "Options:")
            (println (:summary parsed))
            (when errors
              (println)
              (println "Errors:")
              (doseq [e errors] (println e)))
            (System/exit (if errors 1 0)))
          ((:fn command) (:options parsed))))
      (do (usage)
          (System/exit 1)))))

(defn -main [& args]
  (dispatch args))

(comment

  (collect {:snapshot-dir "snapshots"})

  (serve {:snapshot-dir "snapshots"})

  (report {:format :xlsx :snapshot-dir "snapshots" :output-dir "."})

  (visualize []))
