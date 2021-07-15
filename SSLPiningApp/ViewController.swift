//
//  ViewController.swift
//  SSLPiningApp
//
//  Created by Ashish Awasthi on 7/15/21.
//

import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    @IBAction func didSelectSSLCertificateRequest(_ sender: Any) {
        SSLPiningPresenter().makeRequest(req: .certificate) { message in
            let alert = UIAlertController(title: "SSLPinning", message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    @IBAction func didSelectSSLPublicKeyRequest(_ sender: Any) {
        SSLPiningPresenter().makeRequest(req: .publicKey) { message in
            let alert = UIAlertController(title: "SSLPinning", message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }
}

