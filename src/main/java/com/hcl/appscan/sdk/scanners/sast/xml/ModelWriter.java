/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2022. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast.xml;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;

import com.hcl.appscan.sdk.scanners.sast.targets.ISASTTarget;


/**
 * Base implementation of a model writer.  Subclasses define the logic to write
 * specific fragments of the scan model to disk.
 */
public abstract class ModelWriter {
	/**
	 * Instance of a document builder, initialized only after {@link #initialize(File)} is called.
	 */
	protected DocumentBuilder m_builder;

	/**
	 * Instance of a transformer, initialized only after {@link #initialize(File)} is called.
	 */
	protected Transformer m_transformer;

	/**
	 * Initializes this model writer.
	 * 
	 * @param directory The directory where the scan is stored.
	 * @throws ParserConfigurationException If a problem occurs initializing the document builder
	 * @throws TransformerConfigurationException If a problem occurs initializing the transformer
	 * @throws IOException If a problem occurs initializing the internal writers.
	 */
	public final void initialize(File directory) 
			throws ParserConfigurationException , TransformerConfigurationException, IOException {

		initDocumentBuilder();
		initTransformer();
		//initWriters(directory);
	}
	/**
	 * Subclasses can override this to configure the document builder factory.
	 * The default implementation does nothing.
	 * 
	 * @param factory The document builder factory.
	 */
	protected void configureDocumentBuilderFactory(DocumentBuilderFactory factory) {
		// subclass to override
	}


	/**
	 * Subclasses can override this to configure the transformer factory.
	 * The default implementation does nothing.
	 * 
	 * @param factory The transformer factory.
	 */
	protected void configureTransformerFactory(TransformerFactory factory) {
		// subclass to override
	}

	/**
	 * Subclasses can override this to configure the transformer.
	 */
	protected void configureTransformer() {
		m_transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");			//$NON-NLS-1$
		m_transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 							//$NON-NLS-1$
		m_transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");	//$NON-NLS-1$ //$NON-NLS-2$
	}

	/*
	 * Initializes the transformer.
	 */
	private void initTransformer() throws TransformerConfigurationException {
		TransformerFactory factory = TransformerFactory.newInstance();
		configureTransformerFactory(factory);
		m_transformer = factory.newTransformer();
		configureTransformer();
	}

	/*
	 * Initializes the document builder.
	 */
	private void initDocumentBuilder() throws ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		configureDocumentBuilderFactory(factory);
		m_builder = factory.newDocumentBuilder();
	}


	/**
	 * Initializes the internal writers typically there is one writer for each fragment of the 
	 * scan model to write.
	 * 
	 * @param directory The directory where the model files are.
	 * @throws IOException If a problem occurs initializing the internal writers.
	 */
	public abstract void initWriters(File directory) throws IOException;

	/**
	 * Write out to disk.
	 * 
	 * @throws TransformerException If a problem occurs during the write.
	 */
	public abstract void write() throws TransformerException;

	public abstract String getOutputLocation();

	public abstract void visit(List<ISASTTarget> targets, boolean isThirdPartyScanningEnabled, boolean isOpenSourceOnlyEnabled, boolean isSourceCodeOnlyEnabled, boolean isStaticAnalysisOnlyEnabled, boolean isSecretsScanningDisabled, boolean isSecretsScanningOnlyEnabled);
}
